# eBPF CCA

Evaluating eBPF as a Platform for Congestion Control Algorithm Implementation.

Required packages:

```sh
$ sudo apt install clang libbpf-dev bpftool bpfcc-tools libbpfcc libbpfcc-dev linux-headers-$(uname -r)
```

## Running BPF Cubic

> Source files were taken from Linux kernel (commit hash: `c964ced7726294d40913f2127c3f185a92cb4a41`). The following additional modification was made to `bpf_cubic.c` to satisfy the verifier.

```diff
< 	shift = (a >> (b * 3));
---
> 	shift = ((__u32)a >> (b * 3));
```

### Build, register, and set CCA

```sh
# Build eBPF program
$ cd bpf_cubic/
bpf_cubic $ make build
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang-14 -target bpf -I/usr/include/-linux-gnu -g -O2 -o bpf_cubic.o -c bpf_cubic.c

# Register eBPF program
bpf_cubic $ sudo bpftool struct_ops register bpf_cubic.o
Registered tcp_congestion_ops cubic id 101

# Set TCP congestion control algorithm to bpf_cubic
bpf_cubic $ sudo sysctl -w net.ipv4.tcp_congestion_control=bpf_cubic
net.ipv4.tcp_congestion_control = bpf_cubic
```

### Unregister CCA

```
$ sudo bpftool struct_ops unregister name cubic
Unregistered tcp_congestion_ops cubic id 101
```
