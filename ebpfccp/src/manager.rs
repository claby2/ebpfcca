use anyhow::Result;
use libbpf_rs::{MapCore, RingBufferBuilder, MapFlags};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::datapath;

pub type SocketId = u32;
pub type SocketAddr = u64;

// Bidirectional map between socket ID and socket address.
#[derive(Debug, Default)]
struct SocketMap {
    id_to_addr: HashMap<SocketId, SocketAddr>,
    addr_to_id: HashMap<SocketAddr, SocketId>,
}

impl SocketMap {
    fn insert(&mut self, id: SocketId, addr: SocketAddr) {
        self.id_to_addr.insert(id, addr);
        self.addr_to_id.insert(addr, id);
    }

    fn remove_addr(&mut self, addr: SocketAddr) {
        if let Some(id) = self.addr_to_id.remove(&addr) {
            self.id_to_addr.remove(&id);
        }
    }

    fn get_id(&self, addr: SocketAddr) -> Option<SocketId> {
        self.addr_to_id.get(&addr).copied()
    }

    fn get_addr(&self, id: SocketId) -> Option<SocketAddr> {
        self.id_to_addr.get(&id).copied()
    }

    fn unused_id(&self) -> SocketId {
        let mut id = 0;
        while self.id_to_addr.contains_key(&id) {
            id += 1;
        }
        id
    }

    fn get_all_ids(&self) -> Vec<SocketId> {
        self.id_to_addr.keys().copied().collect()
    }
}

// copied from https://stackoverflow.com/a/42186553
unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::core::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::core::mem::size_of::<T>(),
    )
}

#[derive(Debug, Default)]
pub struct Manager {
    socket_map: Arc<Mutex<SocketMap>>,
}

impl Manager {
    pub fn get_socket_id(&self, addr: SocketAddr) -> Option<SocketId> {
        self.socket_map.lock().unwrap().get_id(addr)
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

    pub fn poll_signals(&self, skel: &datapath::DatapathSkel) -> Result<()> {
        self.poll(&skel.maps.signals, |data| {
            let mut event = datapath::types::signal::default();
            plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
            // dbg!(event);
            0
        })
    }

    pub fn poll_create_conn_events(&self, skel: &datapath::DatapathSkel) -> Result<()> {
        let socket_map = self.socket_map.clone();
        self.poll(&skel.maps.create_conn_events, move |data| {
            let mut event = datapath::types::create_conn_event::default();
            plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
            println!("Create conn event: {:?}", event);
            let mut socket_map = socket_map.lock().unwrap();
            let id = socket_map.unused_id();
            socket_map.insert(id, event.sock_addr);
            0
        })
    }

    pub fn poll_free_conn_events(&self, skel: &datapath::DatapathSkel) -> Result<()> {
        let socket_map = self.socket_map.clone();
        self.poll(&skel.maps.free_conn_events, move |data| {
            let mut event = datapath::types::free_conn_event::default();
            plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
            println!("Free conn event: {:?}", event);
            let mut socket_map = socket_map.lock().unwrap();
            socket_map.remove_addr(event.sock_addr);
            0
        })
    }

    pub fn update_cwnd_for_socket(&self, skel: &datapath::DatapathSkel, id: SocketId, cwnd: u32) {
        let socket_addr = self.socket_map.lock().unwrap().get_addr(id);
        if let Some(addr) = socket_addr {
            let conn = datapath::types::connection { 
                cwnd: cwnd,
            };
            let conn_bytes = unsafe { any_as_u8_slice(&conn) };
            let _ = skel.maps.connections.update(&addr.to_ne_bytes(), conn_bytes, MapFlags::ANY);
        }
    }

    pub fn get_all_socket_ids(&self) -> Vec<SocketId> {
        self.socket_map.lock().unwrap().get_all_ids()
    }
}
