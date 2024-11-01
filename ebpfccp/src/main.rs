use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    Result, RingBufferBuilder,
};
use plain::Plain;
use std::{mem::MaybeUninit, time::Duration};

#[allow(unused_imports)]
mod datapath {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/datapath.skel.rs"
    ));
}

unsafe impl Plain for datapath::types::signal {}

fn handle_signal(data: &[u8]) -> i32 {
    let mut event = datapath::types::signal::default();
    // plain will transform the bytes into the struct as defined in the BPF program.
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
    dbg!(event.bytes_acked);
    0
}

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

    let mut ring_builder = RingBufferBuilder::new();
    ring_builder.add(&skel.maps.signals, handle_signal)?;
    let ring = ring_builder.build()?;

    loop {
        // Poll all open ring buffers until timeout is reached or when there are no more events.
        ring.poll(Duration::from_millis(100))?;
    }
}
