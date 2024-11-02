use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore, MapFlags, RingBufferBuilder,
};
use plain::Plain;
use rustyline::{error::ReadlineError, DefaultEditor};
use std::{
    collections::HashMap,
    mem::MaybeUninit,
    sync::{Arc, Mutex},
    time::Duration,
};

#[allow(unused_imports)]
mod datapath {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/datapath.skel.rs"
    ));
}

unsafe impl Plain for datapath::types::signal {}
unsafe impl Plain for datapath::types::connection {}
unsafe impl Plain for datapath::types::create_conn_event {}
unsafe impl Plain for datapath::types::free_conn_event {}

struct Manager {
    // Map eBPF socket id (which is just the address of the socket) to a
    // manually assigned id.
    socket_map: Arc<Mutex<HashMap<u64, u32>>>,
}

impl Manager {
    fn new() -> Self {
        Self {
            socket_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get_socket_id(&self, socket_addr: u64) -> Option<u32> {
        let socket_map = self.socket_map.lock().unwrap();
        socket_map.get(&socket_addr).copied()
    }

    // Generic poll function that can be used to poll any ring buffer.
    fn poll(&self, map: &dyn MapCore, callback: impl Fn(&[u8]) -> i32 + 'static) -> Result<()> {
        let mut ring_builder = RingBufferBuilder::new();
        ring_builder.add(map, callback)?;
        let ring = ring_builder.build()?;
        std::thread::spawn(move || loop {
            // Poll all open ring buffers until timeout is reached or when there are no more events.
            if let Err(e) = ring.poll(Duration::MAX) {
                eprintln!("Error polling ring buffer: {:?}", e);
                std::process::exit(1);
            }
        });
        Ok(())
    }

    fn poll_signals(&self, skel: &datapath::DatapathSkel) -> Result<()> {
        self.poll(&skel.maps.signals, |data| {
            let mut event = datapath::types::signal::default();
            plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
            // dbg!(event);
            0
        })
    }

    fn poll_create_conn_events(&self, skel: &datapath::DatapathSkel) -> Result<()> {
        self.poll(&skel.maps.create_conn_events, |data| {
            let mut event = datapath::types::create_conn_event::default();
            plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
            println!("Create conn event: {:?}", event);
            0
        })
    }

    fn poll_free_conn_events(&self, skel: &datapath::DatapathSkel) -> Result<()> {
        self.poll(&skel.maps.free_conn_events, |data| {
            let mut event = datapath::types::free_conn_event::default();
            plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
            println!("Free conn event: {:?}", event);
            0
        })
    }
}

fn main() -> Result<()> {
    let mut skel_builder = datapath::DatapathSkelBuilder::default();

    skel_builder.obj_builder.debug(true); // Enable debug mode

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    // We could technically modify the BPF program through open_skel here, I do not see much
    // reason for this for now.

    let mut skel = open_skel.load()?;
    let _link = skel.maps.ebpfccp.attach_struct_ops()?;

    // At this point, the BPF program is loaded and attached to the kernel.
    // We should be able to see the CCA in `/proc/sys/net/ipv4/tcp_available_congestion_control`.

    let manager = Manager::new();
    manager.poll_signals(&skel)?;
    manager.poll_create_conn_events(&skel)?;
    manager.poll_free_conn_events(&skel)?;

    let mut rl = DefaultEditor::new()?;
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                match tokens.as_slice() {
                    ["exit"] => break,
                    ["list", "connections"] => {
                        for key in skel.maps.connections.keys() {
                            let conn_bytes = skel.maps.connections.lookup(&key, MapFlags::ANY)?;
                            let key: u64 = *plain::from_bytes(&key)
                                .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))?;
                            if let Some(conn_bytes) = conn_bytes {
                                let conn =
                                    plain::from_bytes::<datapath::types::connection>(&conn_bytes)
                                        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))?;
                                println!(
                                    "{} (sid: {:?}): {:?}",
                                    key,
                                    manager.get_socket_id(key),
                                    conn
                                );
                            }
                        }
                    }
                    _ => {
                        eprintln!("Invalid command");
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                break;
            }
        }
    }
    Ok(())
}
