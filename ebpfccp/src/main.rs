mod datapath;
mod manager;

use crate::manager::Manager;
use anyhow::Result;
use datapath::Skeleton;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore, MapFlags,
};
use rustyline::{error::ReadlineError, DefaultEditor};
use std::mem::MaybeUninit;

fn main() -> Result<()> {
    let mut open_object = MaybeUninit::uninit();
    let mut skel = Skeleton::load(&mut open_object)?;

    let mut manager = Manager::new()?;

    manager.start(&skel)?;

    let mut rl = DefaultEditor::new()?;
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                match tokens.as_slice() {
                    ["exit"] => break,
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
