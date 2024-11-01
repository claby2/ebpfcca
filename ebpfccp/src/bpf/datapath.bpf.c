#include "bpf_cubic.h"
#include <bpf/bpf_tracing.h>

SEC("struct_ops")
void BPF_PROG(init, struct sock *sk)
{
    bpf_cubic_init(sk);
}

SEC("struct_ops")
void BPF_PROG(cwnd_event, struct sock *sk, enum tcp_ca_event event)
{
    bpf_cubic_cwnd_event(sk, event);
}

SEC("struct_ops")
void BPF_PROG(cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
    bpf_cubic_cong_avoid(sk, ack, acked);
}

SEC("struct_ops")
__u32 BPF_PROG(ssthresh, struct sock *sk)
{
    return bpf_cubic_recalc_ssthresh(sk);
}

SEC("struct_ops")
void BPF_PROG(set_state, struct sock *sk, __u8 new_state)
{
    bpf_cubic_state(sk, new_state);
}

SEC("struct_ops")
void BPF_PROG(pckts_acked, struct sock *sk, const struct ack_sample *sample)
{
    bpf_cubic_acked(sk, sample);
}


SEC("struct_ops")
__u32 BPF_PROG(undo_cwnd, struct sock *sk)
{
    return bpf_cubic_undo_cwnd(sk);
}

SEC(".struct_ops")
struct tcp_congestion_ops ebpfccp = {
	.init		= (void *)init,
	.ssthresh	= (void *)ssthresh,
	.cong_avoid	= (void *)cong_avoid,
	.set_state	= (void *)set_state,
	.undo_cwnd	= (void *)undo_cwnd,
	.cwnd_event	= (void *)cwnd_event,
	.pkts_acked     = (void *)pckts_acked,
	.name		= "ebpfccp",
};
