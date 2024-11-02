use plain::Plain;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bpf/datapath.skel.rs"
));

unsafe impl Plain for types::signal {}
unsafe impl Plain for types::connection {}
unsafe impl Plain for types::create_conn_event {}
unsafe impl Plain for types::free_conn_event {}
