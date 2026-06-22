#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>


typedef struct s_ARP
{
	uint16_t	htype;
	uint16_t	ptype;
	uint8_t		hlen;
	uint8_t		plen;
	uint16_t	oper;
	uint8_t		sha[6];
	uint32_t	spa;
	uint8_t		tha[6];
	uint32_t	tpa;
}	__attribute__((packed)) t_ARP;


typedef struct s_ETH
{
	uint8_t		dst[6];
	uint8_t		src[6];
	uint16_t	proto;
}	__attribute__((packed)) t_ETH;

typedef struct s_frame
{
	t_ETH	header;
	t_ARP	pkg_arp;
} __attribute__((packed)) t_frame;
