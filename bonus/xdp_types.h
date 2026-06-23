#ifndef xdp_types
# define xdp_types

#include <linux/bpf.h>
#include <linux/types.h>

typedef struct s_ARP
{
	__u16	htype;
	__u16	ptype;
	__u8		hlen;
	__u8		plen;
	__u16	oper;
	__u8		sha[6];
	__u32	spa;
	__u8		tha[6];
	__u32	tpa;
}	__attribute__((packed)) t_ARP;


typedef struct s_ETH
{
	__u8		dst[6];
	__u8		src[6];
	__u16	proto;
}	__attribute__((packed)) t_ETH;

typedef struct s_frame
{
	t_ETH	header;
	t_ARP	pkg_arp;
} __attribute__((packed)) t_frame;

#endif
