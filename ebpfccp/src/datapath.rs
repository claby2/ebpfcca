use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    Link, MapCore, MapFlags, OpenObject, RingBufferBuilder,
};
use plain::Plain;
use std::{
    mem::MaybeUninit,
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::Duration,
};

// Encapsulating this inside an internal module to avoid leaking everything.
mod internal {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/datapath.skel.rs"
    ));
}

unsafe impl Plain for internal::types::signal {}
unsafe impl Plain for internal::types::connection {}
unsafe impl Plain for internal::types::create_conn_event {}
unsafe impl Plain for internal::types::free_conn_event {}

pub type Signal = internal::types::signal;

pub type CreateConnEvent = internal::types::create_conn_event;

pub type FreeConnEvent = internal::types::free_conn_event;

#[derive(Debug)]
pub enum ConnectionMessage {
    SetCwnd(u64, u32), // SocketAddr, packets in send_cwnd
    SetRateAbs(u64, u32), // SocketAddr, bytes/second for sk_pacing_rate
}

/// Convenience wrapper around the generated skeleton.
pub struct Skeleton {
    skel: &'static internal::DatapathSkel<'static>,
    tx: Sender<ConnectionMessage>,
    rx: Option<Receiver<ConnectionMessage>>,

    // This represents the link to the struct_ops program.
    // As long as this is alive, the struct_ops program will be attached to the kernel.
    // There is no actual use for this in the current implementation, but it is kept here
    // to ensure that the struct_ops program stays alive while the Skeleton is alive.
    _link: Link,
}

// Generic poll function that can be used to poll any ring buffer.
fn poll(map: &dyn MapCore, callback: impl Fn(&[u8]) -> i32 + 'static) -> Result<()> {
    let mut ring_builder = RingBufferBuilder::new();
    ring_builder.add(map, callback)?;
    let ring = ring_builder.build()?;
    thread::spawn(move || loop {
        // Poll all open ring buffers until timeout is reached or when there are no more events.
        if let Err(e) = ring.poll(Duration::MAX) {
            eprintln!("Error polling ring buffer: {:?}", e);
            std::process::exit(1);
        }
    });
    Ok(())
}

// copied from https://stackoverflow.com/a/42186553
unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::core::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>())
}

impl Skeleton {
    pub fn load() -> Result<Self> {
        let open_object = MaybeUninit::uninit();
        let open_object_box = Box::new(open_object);
        let open_object_static_ref: &'static mut MaybeUninit<OpenObject> =
            Box::leak(open_object_box);

        let skel_builder = internal::DatapathSkelBuilder::default();

        //skel_builder.obj_builder.debug(true); // Enable debug mode

        let open_skel = skel_builder.open(open_object_static_ref)?;

        // We could technically modify the BPF program through open_skel here, I do not see much
        // reason for this for now.

        let mut skel = open_skel.load()?;
        let link = skel.maps.ebpfccp.attach_struct_ops()?;

        // At this point, the BPF program is loaded and attached to the kernel.
        // We should be able to see the CCA in `/proc/sys/net/ipv4/tcp_available_congestion_control`.

        let skel_box = Box::new(skel);
        let skel_static_ref: &'static internal::DatapathSkel = Box::leak(skel_box);

        let (tx, rx) = mpsc::channel();

        Ok(Skeleton {
            skel: skel_static_ref,
            tx,
            rx: Some(rx),
            _link: link,
        })
    }

    pub fn sender(&self) -> Sender<ConnectionMessage> {
        self.tx.clone()
    }

    pub fn poll_signals(&self, callback: impl Fn(&Signal) + 'static) -> Result<()> {
        poll(&self.skel.maps.signals, move |data| {
            let mut signal = Signal::default();
            plain::copy_from_bytes(&mut signal, data).unwrap();
            callback(&signal);
            0
        })?;
        Ok(())
    }

    pub fn poll_create_conn_events(
        &self,
        callback: impl Fn(&CreateConnEvent) + 'static,
    ) -> Result<()> {
        poll(&self.skel.maps.create_conn_events, move |data| {
            let mut event = CreateConnEvent::default();
            plain::copy_from_bytes(&mut event, data).unwrap();
            callback(&event);
            0
        })?;
        Ok(())
    }

    pub fn poll_free_conn_events(&self, callback: impl Fn(&FreeConnEvent) + 'static) -> Result<()> {
        poll(&self.skel.maps.free_conn_events, move |data| {
            let mut event = FreeConnEvent::default();
            plain::copy_from_bytes(&mut event, data).unwrap();
            callback(&event);
            0
        })?;
        Ok(())
    }

    pub fn handle_conn_messages(&mut self) -> Result<()> {
        let rx = self.rx.take().expect("Receiver already taken");
        let skel = self.skel;
        thread::spawn(move || loop {
            match rx.recv() {
                Ok(ConnectionMessage::SetCwnd(sock_addr, cwnd)) => {
                    let socket_addr = sock_addr.to_ne_bytes();
                    let conn_opt = skel.maps.connections
                        .lookup(&socket_addr, MapFlags::ANY)
                        .unwrap();
                    if let Some(conn_bytes) = conn_opt {
                            let mut conn = internal::types::connection::default();
                            plain::copy_from_bytes(&mut conn, &conn_bytes[..]).unwrap();
                            conn.cwnd = cwnd;
                            let conn_bytes = unsafe { any_as_u8_slice(&conn) };
                            skel.maps
                                .connections
                                .update(&socket_addr, conn_bytes, MapFlags::ANY)
                                .unwrap();
                    }
                }
                Ok(ConnectionMessage::SetRateAbs(sock_addr, rate)) => {
                    let socket_addr = sock_addr.to_ne_bytes();
                    let conn_opt = skel.maps.connections
                        .lookup(&socket_addr, MapFlags::ANY)
                        .unwrap();
                    if let Some(conn_bytes) = conn_opt {
                            let mut conn = internal::types::connection::default();
                            plain::copy_from_bytes(&mut conn, &conn_bytes[..]).unwrap();
                            conn.pacing_rate = rate;
                            let conn_bytes = unsafe { any_as_u8_slice(&conn) };
                            skel.maps
                                .connections
                                .update(&socket_addr, conn_bytes, MapFlags::ANY)
                                .unwrap();
                    }
                }
                Err(e) => {
                    eprintln!("Error receiving message: {:?}", e);
                    break;
                }
            }
        });
        Ok(())
    }
}
