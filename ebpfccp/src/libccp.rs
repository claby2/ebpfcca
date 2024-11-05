// The bindings seem to make *everything* public, so we wrap them in a module and expose only what
// we need.
mod internal {
    include!(concat!(env!("OUT_DIR"), "/libccp.rs"));
}

unsafe extern "C" fn my_set_cwnd(conn: *mut internal::ccp_connection, cwnd: internal::u32_) {
    println!("set_cwnd called with cwnd: {}", cwnd);
}

unsafe extern "C" fn my_set_rate_abs(conn: *mut internal::ccp_connection, rate: internal::u32_) {
    println!("set_rate_abs called with rate: {}", rate);
}

pub struct Datapath {
    datapath: internal::ccp_datapath,
}

impl Datapath {
    pub fn new() -> Self {
        todo!();
    }
}
