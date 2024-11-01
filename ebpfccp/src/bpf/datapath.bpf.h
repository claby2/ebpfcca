#ifndef DATAPATH_BPF_H
#define DATAPATH_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct signal {
  // newly acked, in-order bytes
  u32 bytes_acked;

  // newly acked, in-order packets
  u32 packets_acked;

  // out-of-order packets
  u32 packets_misordered;
  // TODO: Add more congestion primitives
  //       See `ccp_primitives` in ccp-project/libccp cpp.h
  //       for more information
};

// dummy signal, this is needed so user-land can access the struct information
struct signal _signal = {0};

enum command_type {
  now = 0,
} _command_type = {0};

struct command_request {
  enum command_type t;
  u32 value;
} _command_request = {0};

struct command_response {
  enum command_type t;
  u32 value;
};

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
