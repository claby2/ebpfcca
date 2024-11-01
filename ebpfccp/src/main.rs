use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    Result,
};
use std::mem::MaybeUninit;

#[allow(unused_imports)]
mod datapath {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/datapath.skel.rs"
    ));
}

fn main() -> Result<()> {
    let mut skel_builder = datapath::DatapathSkelBuilder::default();

    skel_builder.obj_builder.debug(true); // Enable debug mode

    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object)?;

    let mut skel = open_skel.load()?;
    let _link = skel.maps.cubic.attach_struct_ops()?;

    // At this point, the BPF program is loaded and attached to the kernel.
    // We should be able to see the CCA in `/proc/sys/net/ipv4/tcp_available_congestion_control`.

    // Sleep for 3 seconds
    std::thread::sleep(std::time::Duration::from_secs(3));

    // After this, the BPF program will be detached from the kernel.

    Ok(())
}
