use anyhow::Result;
use libbpf_rs::{MapCore, MapFlags, RingBufferBuilder};
use libccp::{self, CongestionOps, DatapathOps};
use std::{
    collections::HashMap,
    os::unix::net::UnixDatagram,
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::datapath::Skeleton;

const FROM_CCP_SOCKET: &str = "/tmp/ccp/0/out";
const TO_CCP_SOCKET: &str = "/tmp/ccp/0/in";

/// Socket interface to communicate with CCP congestion control algorithm
#[derive(Debug)]
pub struct SocketOperator {
    socket: UnixDatagram,
}

impl SocketOperator {
    pub fn new() -> Result<Self> {
        let socket = UnixDatagram::bind(TO_CCP_SOCKET)?;
        Ok(Self { socket })
    }
}

impl DatapathOps for SocketOperator {
    fn send_msg(&mut self, msg: &[u8]) {
        todo!("Send message to CCP congestion control algorithm");
    }
}

/// Manage connection-level state and operations
#[derive(Debug)]
pub struct Connection {}

impl CongestionOps for Connection {
    fn set_cwnd(&mut self, cwnd: u32) {
        todo!("Set congestion window");
    }

    fn set_rate_abs(&mut self, rate: u32) {
        todo!("Set rate");
    }
}

pub struct Manager {
    datapath: libccp::Datapath,
}

impl Manager {
    pub fn new() -> Result<Self> {
        let so = SocketOperator::new()?;
        let datapath = libccp::DatapathBuilder::default()
            .with_ops(so)
            .with_id(0)
            .init()?;
        Ok(Self { datapath })
    }

    pub fn start(&mut self, skeleton: &Skeleton) -> Result<()> {
        skeleton.poll_signals(move |signal| {
            println!("Received signal");
        })?;

        skeleton.poll_create_conn_events(move |event| {
            println!("Received create connection event");
        })?;

        skeleton.poll_free_conn_events(move |event| {
            println!("Received free connection event");
        })?;

        Ok(())
    }
}
