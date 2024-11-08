mod datapath;
mod manager;

use crate::manager::Manager;
use anyhow::Result;
use datapath::Skeleton;
use rustyline::{error::ReadlineError, DefaultEditor};

fn main() -> Result<()> {
    let mut manager = Manager::new()?;

    let mut skel = Skeleton::load()?;
    manager.start(&skel)?;
    skel.handle_conn_messages()?;

    let mut rl = DefaultEditor::new()?;
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                match tokens.as_slice() {
                    ["exit"] => break,
                    ["list", "connections"] => {
                        manager.list_connections();
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
