mod datapath;
#[allow(warnings)]
mod libccp;
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
