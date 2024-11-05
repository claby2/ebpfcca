# eBPF-CCP

Implementing a CCP (Congestion Control Plane) datapath using eBPF

Required packages:
Install rustc and cargo using Rustup (https://www.rust-lang.org/tools/install)
```sh
$ sudo apt install clang libbpf-dev bpftool bpfcc-tools libbpfcc libbpfcc-dev linux-headers-$(uname -r) pkg-config
```

## Running eBPF-CCP

> The eBPF program under bpf/ is partially adopted from the CCP Kernel Module Datapath
https://github.com/ccp-project/ccp-kernel Commit 264554a50a247a512c8d22248b92a84512e4d01c
```

### Build, register, and set CCA

```sh
# Build eBPF-CCP
$ cargo run --release

# Register eBPF-CCP and open REPL
$ cd target/release
$ sudo ebpfccp

# Switch TCP congestion control algorithm to ebpfccp
$ sudo sysctl -w net.ipv4.tcp_congestion_control=ebpfccp
```

### REPL Commands

```sh
# exit
>> exit

# Show all active TCP connections
>> list connections

# Set the sending congestion window of a certain socket_id
# cwnd_bytes is rounded down to the closest multiple of mss
>> set cwnd [socket_id] [cwnd_bytes]

# Set the sending congestion window of all socket_ids
>> set cwnd all [cwnd_bytes]
```

### Switch away and unregister eBPF-CCP

```
$ sudo sysctl -w net.ipv4.tcp_congestion_control=cubic
$ sudo bpftool struct_ops unregister name ebpfccp
```
