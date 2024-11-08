use anyhow::Result;
use libccp::{self, CongestionOps, DatapathOps};
use std::{
    collections::HashMap,
    fs,
    ops::Deref,
    os::unix::net::UnixDatagram,
    path::Path,
    sync::{mpsc::Sender, Arc, RwLock},
    thread,
};

use crate::datapath::{ConnectionMessage, Skeleton};

const PORTUS_SOCKET: &str = "/tmp/ccp/portus";
const EBPFCCP_SOCKET: &str = "/tmp/ccp/ebpfccp";

/// Socket interface to communicate with CCP congestion control algorithm
#[derive(Debug)]
struct SocketOperator {
    socket: UnixDatagram,
}

impl SocketOperator {
    fn new() -> Result<Self> {
        // Remove the socket if it already exists
        if Path::new(EBPFCCP_SOCKET).exists() {
            fs::remove_file(EBPFCCP_SOCKET)?;
        }

        let socket = UnixDatagram::bind(EBPFCCP_SOCKET)?;
        Ok(Self { socket })
    }

    fn send(&mut self, msg: &[u8]) -> Result<usize> {
        let size = self.socket.send_to(msg, PORTUS_SOCKET)?;
        Ok(size)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let size = self.socket.recv(buf)?;
        Ok(size)
    }
}

#[derive(Debug)]
struct SharedSocketOperator(Arc<RwLock<SocketOperator>>);

impl Clone for SharedSocketOperator {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl DatapathOps for SharedSocketOperator {
    fn send_msg(&mut self, msg: &[u8]) {
        self.0
            .write()
            .unwrap()
            .send(msg)
            .expect("Failed to send message");
    }
}

impl Deref for SharedSocketOperator {
    type Target = Arc<RwLock<SocketOperator>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Manage connection-level state and operations
#[derive(Debug)]
pub struct Connection {
    socket_addr: u64,
    sender: Sender<ConnectionMessage>,
}

impl Connection {
    fn new(socket_addr: u64, sender: Sender<ConnectionMessage>) -> Self {
        Self {
            socket_addr,
            sender,
        }
    }
}

impl CongestionOps for Connection {
    fn set_cwnd(&mut self, cwnd: u32) {
        self.sender
            .send(ConnectionMessage::SetCwnd(self.socket_addr, cwnd))
            .unwrap();
    }

    fn set_rate_abs(&mut self, rate: u32) {
        self.sender
            .send(ConnectionMessage::SetRateAbs(self.socket_addr, rate))
            .unwrap();
    }
}

/// Manager for handling connections and datapath operations
pub struct Manager {
    datapath: Arc<&'static libccp::Datapath>,
    connections: Arc<RwLock<HashMap<u64, libccp::Connection<'static, Connection>>>>,
    socket_operator: SharedSocketOperator,
}

impl Manager {
    pub fn new() -> Result<Self> {
        let shared_socket_operator =
            SharedSocketOperator(Arc::new(RwLock::new(SocketOperator::new()?)));
        let dp = libccp::DatapathBuilder::default()
            .with_ops(shared_socket_operator.clone())
            .with_id(0)
            .init()?;

        // Leak the datapath reference to make it static
        let dp_box = Box::new(dp);
        let dp_static_ref: &'static libccp::Datapath = Box::leak(dp_box);

        Ok(Self {
            datapath: Arc::new(dp_static_ref),
            connections: Arc::new(RwLock::new(HashMap::new())),
            socket_operator: shared_socket_operator,
        })
    }

    pub fn start(&mut self, skeleton: &Skeleton) -> Result<()> {
        // Start receiving messages from the socket
        self.receive_messages();

        // Poll for signals
        self.poll_signals(skeleton)?;

        // Poll for create connection events
        self.create_conn_events(skeleton)?;

        // Poll for free connection events
        self.free_conn_events(skeleton)?;

        Ok(())
    }

    fn receive_messages(&mut self) {
        let socket_operator = self.socket_operator.clone();
        let dp = self.datapath.clone();
        thread::spawn(move || {
            let mut buf = [0; 1024];
            loop {
                let size = socket_operator.read().unwrap().recv(&mut buf).unwrap();
                dp.recv_msg(&mut buf[..size]).unwrap();
            }
        });
    }

    fn poll_signals(&mut self, skeleton: &Skeleton) -> Result<()> {
        let connections = self.connections.clone();
        skeleton.poll_signals(move |signal| {
            // A connection has received a signal: update the connection's primitives
            println!("Received signal");
            signal.sock_addr;
            let mut connections = connections.write().unwrap();

            if let Some(conn) = connections.get_mut(&signal.sock_addr) {
                let primitives = libccp::Primitives::default()
                    .with_bytes_acked(signal.bytes_acked)
                    .with_packets_acked(signal.packets_acked)
                    .with_packets_misordered(signal.packets_misordered);
                // TODO: Add more fields to primitives

                conn.load_primitives(primitives);
            }
        })
    }

    fn create_conn_events(&mut self, skeleton: &Skeleton) -> Result<()> {
        let dp = self.datapath.clone();
        let connections = self.connections.clone();
        let tx = skeleton.sender();
        skeleton.poll_create_conn_events(move |event| {
            // A new flow has been created: create a new connection and store it
            println!("Received create connection event");

            // Create a new connection
            let conn = Connection::new(event.sock_addr, tx.clone());
            let flow_info = libccp::FlowInfo::default()
                .with_init_cwnd(event.init_cwnd)
                .with_mss(event.mss)
                .with_four_tuple(event.src_ip, event.src_port, event.dst_ip, event.dst_port);
            let libccp_connection = libccp::Connection::start(&dp, conn, flow_info).unwrap();

            // Store the connection
            let mut connections = connections.write().unwrap();
            connections.insert(event.sock_addr, libccp_connection);
        })
    }

    fn free_conn_events(&mut self, skeleton: &Skeleton) -> Result<()> {
        let connections = self.connections.clone();
        skeleton.poll_free_conn_events(move |event| {
            // A connection has been freed: remove it from the map
            println!("Received free connection event");
            let mut connections = connections.write().unwrap();
            connections.remove(&event.sock_addr);
        })
    }
}
