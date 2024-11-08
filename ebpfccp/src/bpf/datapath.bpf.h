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

  // out-of-order bytes
  u32 bytes_misordered;

  // out-of-order packets
  u32 packets_misordered;

  // bytes corresponding to ecn-marked packets
  u32 ecn_bytes; // TODO: add ECN support

  // ecn-marked packets
  u32 ecn_packets; // TODO: add ECN support

  // an estimate of the number of packets lost
  u32 lost_pkts_sample;

  bool was_timeout; // TODO: I think we need to handle this differently, perhaps
                    // another event buffer

  // a recent sample of the round-trip time
  u64 rtt_sample_us;

  // sample of the sending rate, bytes / s
  u64 rate_outgoing;
  // sample of the receiving rate, bytes / s
  u64 rate_incoming;

  // the number of actual bytes in flight
  u32 bytes_in_flight;
  // the number of actual packets in flight
  u32 packets_in_flight;

  // the target congestion window to maintain, in bytes
  u32 snd_cwnd;
  // target rate to maintain, in bytes/s
  u64 snd_rate; // TODO: Might be unused?

  // amount of data available to be sent
  // NOT per-packet - an absolute measurement
  u32 bytes_pending;
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

static inline unsigned int tcp_left_out(const struct tcp_sock *tp) {
  return tp->sacked_out + tp->lost_out;
}

static inline unsigned int tcp_packets_in_flight(const struct tcp_sock *tp) {
  return tp->packets_out - tcp_left_out(tp) + tp->retrans_out;
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
