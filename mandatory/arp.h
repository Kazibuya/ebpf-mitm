#ifndef ARP_H
# define ARP_H

#include <net/if.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>

typedef struct s_global
{
    int     sock;
    char    ifname[IF_NAMESIZE];
} t_global;

extern t_global g_data;

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


//error.c
void invalid_mac(char *str);
void invalid_ip(char *str);
void	not_root();
void invalid_inputs();
void	helper();

//getter.c
void get_ipv4(char *str, t_frame *frame, bool who);
void get_mac(char *str, t_frame *frame, bool who);
void get_ifname(char *ifname);
void	check_root();

#endif
