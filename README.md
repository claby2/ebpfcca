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

1. Generate `vmlinux.h` ([libbpf/libbpf-bootstrap#172](https://github.com/libbpf/libbpf-bootstrap/issues/172#issuecomment-1526749499))

```sh
$ sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf_cubic/vmlinux.h
```

2. Compile `bpf_cubic`

```sh
$ cd bpf_cubic/
bpf_cubic $ clang-14 -target bpf -I/usr/include/$(uname -m)-linux-gnu -g -O2 -o bpf_cubic.o -c bpf_cubic.c
```

3. Load eBPF program

```sh
bpf_cubic $ sudo bpftool struct_ops register bpf_cubic.o
```

To unregister the program, list the currently registered programs with `sudo bpftool struct_ops list`, fetch the ID, and unregister with `sudo bpftool struct_ops unregister id <ID>`.
