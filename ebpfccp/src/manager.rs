use anyhow::Result;
use libccp::{self, CongestionOps, DatapathOps};
use std::{
    collections::HashMap,
    fs,
    os::unix::net::UnixDatagram,
    path::Path,
    sync::{Arc, RwLock},
};

use crate::datapath::Skeleton;

const PORTUS_SOCKET: &str = "/tmp/ccp/portus";
const EBPFCCP_SOCKET: &str = "/tmp/ccp/ebpfccp";

/// Socket interface to communicate with CCP congestion control algorithm
#[derive(Debug)]
pub struct SocketOperator {
    socket: UnixDatagram,
}

impl SocketOperator {
    pub fn new() -> Result<Self> {
        // Remove the socket if it already exists
        if Path::new(EBPFCCP_SOCKET).exists() {
            fs::remove_file(EBPFCCP_SOCKET)?;
        }

        let socket = UnixDatagram::bind(EBPFCCP_SOCKET)?;
        Ok(Self { socket })
    }
}

impl DatapathOps for SocketOperator {
    fn send_msg(&mut self, msg: &[u8]) {
        self.socket.send_to(msg, PORTUS_SOCKET).unwrap();
    }
}

/// Manage connection-level state and operations
#[derive(Debug)]
pub struct Connection {}

impl CongestionOps for Connection {
    fn set_cwnd(&mut self, _cwnd: u32) {
        todo!("Set congestion window");
    }

    fn set_rate_abs(&mut self, _rate: u32) {
        todo!("Set rate");
    }
}

pub struct Manager {
    datapath: Arc<RwLock<&'static libccp::Datapath>>,

    // Map from socket address to connection
    connections: Arc<RwLock<HashMap<u64, libccp::Connection<'static, Connection>>>>,
}

impl Manager {
    pub fn new() -> Result<Self> {
        let so = SocketOperator::new()?;
        let dp = libccp::DatapathBuilder::default()
            .with_ops(so)
            .with_id(0)
            .init()?;

        // Leak the datapath reference to make it static
        let dp_box = Box::new(dp);
        let dp_static_ref: &'static libccp::Datapath = Box::leak(dp_box);

        Ok(Self {
            datapath: Arc::new(RwLock::new(dp_static_ref)),
            connections: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn start(&mut self, skeleton: &Skeleton) -> Result<()> {
        skeleton.poll_signals(move |_signal| {
            println!("Received signal");
        })?;

        {
            let dp = self.datapath.clone();
            let connections = self.connections.clone();
            skeleton.poll_create_conn_events(move |event| {
                println!("Received create connection event");
                let dp = dp.read().unwrap();

                // Create a new connection
                let conn = Connection {};
                let flow_info = libccp::FlowInfo::default()
                    .with_init_cwnd(event.init_cwnd)
                    .with_mss(event.mss)
                    .with_four_tuple(event.src_ip, event.src_port, event.dst_ip, event.dst_port);
                let libccp_connection = libccp::Connection::start(&dp, conn, flow_info).unwrap();

                // Store the connection
                let mut connections = connections.write().unwrap();
                connections.insert(event.sock_addr, libccp_connection);
            })?;
        };

        skeleton.poll_free_conn_events(move |_event| {
            println!("Received free connection event");
        })?;

        Ok(())
    }
}
