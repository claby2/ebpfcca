#include "bpf_cubic.h"
#include <bpf/bpf_tracing.h>

struct signal {
  u64 now;
};

struct signal _signal = {0}; // dummy signal

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, sizeof(struct signal) * 1024);
} signals SEC(".maps");

SEC("struct_ops")
void BPF_PROG(init, struct sock *sk) { bpf_cubic_init(sk); }

SEC("struct_ops")
void BPF_PROG(cwnd_event, struct sock *sk, enum tcp_ca_event event) {
  bpf_cubic_cwnd_event(sk, event);
}

SEC("struct_ops")
void BPF_PROG(cong_avoid, struct sock *sk, __u32 ack, __u32 acked) {
  bpf_cubic_cong_avoid(sk, ack, acked);
}

SEC("struct_ops")
__u32 BPF_PROG(ssthresh, struct sock *sk) {
  return bpf_cubic_recalc_ssthresh(sk);
}

SEC("struct_ops")
void BPF_PROG(set_state, struct sock *sk, __u8 new_state) {
  bpf_cubic_state(sk, new_state);
}

SEC("struct_ops")
void BPF_PROG(pckts_acked, struct sock *sk, const struct ack_sample *sample) {
  struct signal *sig;
  sig = bpf_ringbuf_reserve(&signals, sizeof(struct signal), 0);
  if (!sig)
    return;
  sig->now = bpf_ktime_get_ns();
  bpf_ringbuf_submit(sig, 0);

  bpf_cubic_acked(sk, sample);
}

SEC("struct_ops")
__u32 BPF_PROG(undo_cwnd, struct sock *sk) { return bpf_cubic_undo_cwnd(sk); }

SEC(".struct_ops")
struct tcp_congestion_ops ebpfccp = {
    // initialize private data (optional)
    .init = (void *)init,
    // return slow start threshold (required)
    .ssthresh = (void *)ssthresh,
    // do new cwnd calculation (required)
    .cong_avoid = (void *)cong_avoid,
    // call before changing ca_state (optional)
    .set_state = (void *)set_state,
    // new value of cwnd after loss (optional)
    .undo_cwnd = (void *)undo_cwnd,
    // call when cwnd event occurs (optional)
    .cwnd_event = (void *)cwnd_event,
    // hook for packet ack accounting (optional)
    .pkts_acked = (void *)pckts_acked,
    // get info for inet_diag (optional)
    .get_info = NULL,
    .release = NULL,
    .name = "ebpfccp",
};
