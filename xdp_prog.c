#include "xdp_types.h"
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} rb SEC(".maps");

SEC("xdp")
int	xdp_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	t_frame *frame = data;
	if ((void *)(frame + 1) > data_end)
		return XDP_PASS;
	if (frame->header.proto != bpf_htons(0x0806))
		return XDP_PASS;
	// if (frame->pkg_arp.oper != bpf_htons(1))
		// return XDP_PASS;
	t_ARP *pkg = bpf_ringbuf_reserve(&rb, sizeof(t_ARP), 0);
	if (!pkg)
		return XDP_PASS;
	*pkg = frame->pkg_arp;
	bpf_ringbuf_submit(pkg, 0);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
