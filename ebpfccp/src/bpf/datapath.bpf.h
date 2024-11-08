#ifndef DATAPATH_BPF_H
#define DATAPATH_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct connection {
  // in unit of bytes, note that kernel tp->snd_cwnd is in packets - translate
  // by * (1/tp->mss)
  u32 cwnd;
} _connection = {0};

struct signal {
  u64 sock_addr;
  // newly acked, in-order bytes
  u32 bytes_acked;

  // newly acked, in-order packets
  u32 packets_acked;

  // out-of-order packets
  u32 packets_misordered;
  // TODO: Add more congestion primitives
  //       See `ccp_primitives` in ccp-project/libccp cpp.h
  //       for more information
} _signal = {0};

// New connection message
struct create_conn_event {
  u64 sock_addr;
  u32 init_cwnd;
  u32 mss;
  u32 src_ip;
  u32 src_port;
  u32 dst_ip;
  u32 dst_port;
} _create_conn_event = {0};

// Free connection message
struct free_conn_event {
  u64 sock_addr;
} _free_conn_event = {0};

// This represents the per-socket private data
// It can be accessed with inet_csk_ca(sk)
struct ccp {
  // control
  u32 last_snd_una;     // 4 B
  u32 last_bytes_acked; // 8 B
  u32 last_sacked_out;  // 12 B
};

static inline struct inet_connection_sock *inet_csk(const struct sock *sk) {
  return (struct inet_connection_sock *)sk;
}

static inline void *inet_csk_ca(const struct sock *sk) {
  return (void *)inet_csk(sk)->icsk_ca_priv;
}

static inline struct tcp_sock *tcp_sk(const struct sock *sk) {
  return (struct tcp_sock *)sk;
}

#define MTU 1500
#define S_TO_US 1000000
#define MAX_FLOWS 1024

// Copied this from the kernel source code
#define do_div(n, base)                                                        \
  ({                                                                           \
    uint32_t __base = (base);                                                  \
    uint32_t __rem;                                                            \
    __rem = ((uint64_t)(n)) % __base;                                          \
    (n) = ((uint64_t)(n)) / __base;                                            \
    __rem;                                                                     \
  })

#endif
