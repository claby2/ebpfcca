use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore, OpenObject, RingBufferBuilder,
};
use plain::Plain;
use std::{mem::MaybeUninit, time::Duration};

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

pub struct Signal(internal::types::signal);

pub struct Connection(internal::types::connection);

pub struct CreateConnEvent(internal::types::create_conn_event);

pub struct FreeConnEvent(internal::types::free_conn_event);

/// Convenience wrapper around the generated skeleton.
pub struct Skeleton<'a>(internal::DatapathSkel<'a>);

// Generic poll function that can be used to poll any ring buffer.
fn poll(map: &dyn MapCore, callback: impl Fn(&[u8]) -> i32 + 'static) -> Result<()> {
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

impl<'a> Skeleton<'a> {
    pub fn load(open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let mut skel_builder = internal::DatapathSkelBuilder::default();

        //skel_builder.obj_builder.debug(true); // Enable debug mode

        let open_skel = skel_builder.open(open_object)?;

        // We could technically modify the BPF program through open_skel here, I do not see much
        // reason for this for now.

        let mut skel = open_skel.load()?;
        let _link = skel.maps.ebpfccp.attach_struct_ops()?;

        // At this point, the BPF program is loaded and attached to the kernel.
        // We should be able to see the CCA in `/proc/sys/net/ipv4/tcp_available_congestion_control`.

        Ok(Skeleton(skel))
    }

    pub fn poll_signals(&self, callback: impl Fn(&Signal) + 'static) -> Result<()> {
        let _ = poll(&self.0.maps.signals, move |data| {
            let mut signal = internal::types::signal::default();
            plain::copy_from_bytes(&mut signal, data).unwrap();
            callback(&Signal(signal));
            0
        })?;
        Ok(())
    }

    pub fn poll_create_conn_events(
        &self,
        callback: impl Fn(&CreateConnEvent) + 'static,
    ) -> Result<()> {
        let _ = poll(&self.0.maps.create_conn_events, move |data| {
            let mut event = internal::types::create_conn_event::default();
            plain::copy_from_bytes(&mut event, data).unwrap();
            callback(&CreateConnEvent(event));
            0
        })?;
        Ok(())
    }

    pub fn poll_free_conn_events(&self, callback: impl Fn(&FreeConnEvent) + 'static) -> Result<()> {
        let _ = poll(&self.0.maps.free_conn_events, move |data| {
            let mut event = internal::types::free_conn_event::default();
            plain::copy_from_bytes(&mut event, data).unwrap();
            callback(&FreeConnEvent(event));
            0
        })?;
        Ok(())
    }
}
