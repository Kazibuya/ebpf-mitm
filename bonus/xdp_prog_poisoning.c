#include "xdp_types.h"
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8[6]);
} spoof_mac SEC(".maps");

static __always_inline void swap_mac(__u8 *a, __u8 *b)
{
	__u8 tmp[6];
	__builtin_memcpy(tmp, a, 6);
	__builtin_memcpy(a, b, 6);
	__builtin_memcpy(b, tmp, 6);
}

static __always_inline void swap_ipv4(t_ARP *pkg)
{
	__u32 tmp = pkg->spa;
	pkg->spa = pkg->tpa;
	pkg->tpa = tmp;
}

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
	if (frame->pkg_arp.oper != bpf_htons(1))
		return XDP_PASS;
	__u32 key = 0;
	__u8 *spoof = bpf_map_lookup_elem(&spoof_mac, &key);
	if (!spoof)
		return XDP_PASS;
	swap_mac(frame->header.dst, frame->header.src);
	swap_mac(frame->pkg_arp.tha, frame->pkg_arp.sha);
	swap_ipv4(&frame->pkg_arp);
	frame->pkg_arp.oper = bpf_htons(2);
	__builtin_memcpy(frame->pkg_arp.sha, spoof, 6);
	__builtin_memcpy(frame->header.src, spoof, 6);
	t_ARP *pkg = bpf_ringbuf_reserve(&rb, sizeof(t_ARP), 0);
	if (!pkg)
		return XDP_PASS;
	*pkg = frame->pkg_arp;
	bpf_ringbuf_submit(pkg, 0);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
