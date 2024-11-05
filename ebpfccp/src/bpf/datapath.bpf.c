#include "datapath.bpf.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Number of active flows
int num_flows = 0;

// User-space program should be able to edit this map to change TCP parameters
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_FLOWS);
  __type(key, u64); // socket addr
  __type(value, struct connection);
} connections SEC(".maps");

// Ring buffer to send signal events to user-land
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, sizeof(struct signal) * 1024);
} signals SEC(".maps");

// Used to notify user-space when a new connection is created
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, sizeof(struct create_conn_event) * 1024);
} create_conn_events SEC(".maps");

// Used to notify user-space when a connection is freed
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, sizeof(struct free_conn_event) * 1024);
} free_conn_events SEC(".maps");

SEC("struct_ops")
void BPF_PROG(init, struct sock *sk) {
  struct tcp_sock *tp = tcp_sk(sk);
  struct ccp *ca = inet_csk_ca(sk);
  ca->last_bytes_acked = tp->bytes_acked;
  ca->last_sacked_out = tp->sacked_out;
  ca->last_snd_una = tp->snd_una;

  if (num_flows >= MAX_FLOWS) {
    // Too many flows
    return;
  }

  // Use the address of the socket as the socket id
  // TODO: Check if this is a good idea
  // My original idea was to loop through the map and find the first available
  // slot, but it was hard to appease the eBPF verifier as I kept getting
  // "too many instructions" errors
  //
  // Another idea I had was to leverage __sk_common.skc_cookie, but this is
  // an atomic64_t, which I am not entirely sure how to handle in eBPF.
  //
  // Also note that portus (user-space CCP agent) requires the socket id to be
  // u32, so the Rust user-space code will have to handle this conversion.
  // I do not think this should be too difficult, but it is something to keep
  // mind.
  u64 sock_addr = (u64)sk;

  if (bpf_map_lookup_elem(&connections, &sock_addr)) {
    // Connection already exists
    return;
  }

  // Add the connection to the map
  struct connection conn = {.cwnd = tp->snd_cwnd * tp->mss_cache};
  bpf_map_update_elem(&connections, &sock_addr, &conn, BPF_ANY);
  num_flows++;

  // Notify user-space that a new connection has been created
  struct create_conn_event *evt;
  evt = bpf_ringbuf_reserve(&create_conn_events,
                            sizeof(struct create_conn_event), 0);
  if (!evt)
    return;

  // Fill in the message
  evt->sock_addr = sock_addr;
  evt->init_cwnd = tp->snd_cwnd * tp->mss_cache;
  evt->mss = tp->mss_cache;
  evt->src_ip = tp->inet_conn.icsk_inet.inet_saddr;
  evt->src_port = tp->inet_conn.icsk_inet.inet_sport;
  // NOTE: This is a somewhat hacky way to get the destination IP and port
  //       The conventional "kernel module" way would be to use
  //       icsk_inet.inet_daddr and icsk_inet.inet_dport, but those are not
  //       available in vmlinux.h
  evt->dst_ip = sk->__sk_common.skc_daddr;
  evt->dst_port = sk->__sk_common.skc_dport;

  bpf_ringbuf_submit(evt, 0);
}

SEC("struct_ops")
void BPF_PROG(cwnd_event, struct sock *sk, enum tcp_ca_event event) { return; }

void load_signal(struct sock *sk, const struct rate_sample *rs) {
  struct tcp_sock *tp = tcp_sk(sk);
  struct ccp *ca = inet_csk_ca(sk);

  struct signal *sig;

  // Reserve bytes in the ring buffer and get a pointer to the reserved space
  sig = bpf_ringbuf_reserve(&signals, sizeof(struct signal), 0);
  if (!sig)
    return;

  u64 rin = 0;  // send bandwidth in bytes per second
  u64 rout = 0; // recv bandwidth in bytes per second
  u64 ack_us = rs->rcv_interval_us;
  u64 snd_us = rs->snd_interval_us;

  if (ack_us != 0 && snd_us != 0) {
    rin = rout = (u64)rs->delivered * MTU * S_TO_US;
    do_div(rin, snd_us);
    do_div(rout, ack_us);
  }

  sig->bytes_acked = tp->bytes_acked - ca->last_bytes_acked;
  ca->last_bytes_acked = tp->bytes_acked;

  sig->packets_misordered = tp->sacked_out >= ca->last_sacked_out
                                ? tp->sacked_out - ca->last_sacked_out
                                : 0;

  ca->last_sacked_out = tp->sacked_out;

  // TODO: look into why bpf_core_read must be used here
  //       For some reason, this is only needed when I run with Docker...
  u64 acked_sacked;
  bpf_core_read(&acked_sacked, sizeof(acked_sacked), &rs->acked_sacked);
  sig->packets_acked = acked_sacked - sig->packets_misordered;

  // Submit the reserved space to the ring buffer
  bpf_ringbuf_submit(sig, 0);
}

void set_cwnd(struct sock *sk) {
  struct tcp_sock *tp = tcp_sk(sk);

  u64 sock_addr = (u64)sk;
  struct connection *conn = bpf_map_lookup_elem(&connections, &sock_addr);
  if (conn == NULL) {
    // Connection does not exist
    return;
  }
  tp->snd_cwnd = conn->cwnd / tp->mss_cache;
}

SEC("struct_ops")
void BPF_PROG(cong_control, struct sock *sk, const struct rate_sample *rs) {
  load_signal(sk, rs);
  set_cwnd(sk);
}

SEC("struct_ops")
__u32 BPF_PROG(ssthresh, struct sock *sk) { return 0; }

SEC("struct_ops")
void BPF_PROG(set_state, struct sock *sk, __u8 new_state) { return; }

SEC("struct_ops")
void BPF_PROG(pckts_acked, struct sock *sk, const struct ack_sample *sample) {
  return;
}

SEC("struct_ops")
__u32 BPF_PROG(undo_cwnd, struct sock *sk) { return 0; }

SEC("struct_ops")
void BPF_PROG(release, struct sock *sk) {
  // Remove the connection from the map
  u64 sock_addr = (u64)sk;
  bpf_map_delete_elem(&connections, &sock_addr);
  num_flows--;

  // Notify user-space that the connection has been freed
  struct free_conn_event *evt;
  evt =
      bpf_ringbuf_reserve(&free_conn_events, sizeof(struct free_conn_event), 0);
  if (!evt)
    return;
  evt->sock_addr = sock_addr;

  bpf_ringbuf_submit(evt, 0);
}

SEC(".struct_ops")
struct tcp_congestion_ops ebpfccp = {
    .init = (void *)init,
    .ssthresh = (void *)ssthresh,
    .cong_control = (void *)cong_control,
    .set_state = (void *)set_state,
    .undo_cwnd = (void *)undo_cwnd,
    .cwnd_event = (void *)cwnd_event,
    .pkts_acked = (void *)pckts_acked,
    .get_info = NULL,
    .release = (void *)release,
    .name = "ebpfccp",
};
