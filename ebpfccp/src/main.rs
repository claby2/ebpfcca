mod datapath;
mod manager;

use crate::manager::Manager;
use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore, MapFlags,
};
use rustyline::{error::ReadlineError, DefaultEditor};
use std::mem::MaybeUninit;

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

    let manager = Manager::default();
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
                    },
                    ["set", "cwnd", socket_id, cwnd_bytes] => {
                        if *socket_id == "all" {
                            let cwnd_bytes: u32 = cwnd_bytes.parse()?;
                            for key in manager.get_all_socket_ids() {
                                manager.update_cwnd_for_socket(&skel, key, cwnd_bytes);
                            }
                        } else {
                            let socket_id: u32 = socket_id.parse()?;
                            let cwnd_bytes: u32 = cwnd_bytes.parse()?;
                            manager.update_cwnd_for_socket(&skel, socket_id, cwnd_bytes);
                        }
                        
                    },
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
