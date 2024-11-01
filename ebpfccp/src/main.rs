use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    RingBufferBuilder, UserRingBuffer,
};
use plain::Plain;
use rustyline::{error::ReadlineError, DefaultEditor};
use std::{mem::MaybeUninit, time::Duration};

#[allow(unused_imports)]
mod datapath {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/datapath.skel.rs"
    ));
}

unsafe impl Plain for datapath::types::signal {}
unsafe impl Plain for datapath::types::command_type {}
unsafe impl Plain for datapath::types::command_request {}

fn handle_signal(data: &[u8]) -> i32 {
    let mut event = datapath::types::signal::default();
    // plain will transform the bytes into the struct as defined in the BPF program.
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
    dbg!(event);
    0
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

    let mut signals_ring_builder = RingBufferBuilder::new();
    signals_ring_builder.add(&skel.maps.signals, handle_signal)?;
    let signals_ring = signals_ring_builder.build()?;

    std::thread::spawn(move || loop {
        // Poll all open ring buffers until timeout is reached or when there are no more events.
        if let Err(e) = signals_ring.poll(Duration::from_millis(100)) {
            eprintln!("Error polling ring buffer: {:?}", e);
            std::process::exit(1);
        }
    });

    let command_requests_ring = UserRingBuffer::new(&skel.maps.command_requests)?;

    let mut rl = DefaultEditor::new()?;
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                match tokens.as_slice() {
                    ["exit"] => break,
                    ["now"] => {
                        let mut command_request = command_requests_ring
                            .reserve(size_of::<datapath::types::command_request>())?;
                        let bytes = command_request.as_mut();
                        let request =
                            plain::from_mut_bytes::<datapath::types::command_request>(bytes)
                                .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))?;
                        request.t.write(datapath::types::command_type::now);
                        command_requests_ring.submit(command_request)?;
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
