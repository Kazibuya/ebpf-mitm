#ifndef ARP_H
# define ARP_H

#include <stdio.h>
#include <signal.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>

extern int g_sock;

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

void invalid_mac(char *str);
void invalid_ip(char *str);
void not_root();
void fatal_error(char *msg);
void helper();
void get_data(t_frame *frame, t_frame *input_arp, char *ifname, char **argv);
void get_ifname(char *ifname);
void get_ipv4(char *str, t_frame *frame, bool who);
void get_mac(char *str, t_frame *frame, bool who);
void check_root();
size_t ft_strlen(const char *theString);
size_t ft_strlcpy(char *dst, const char *src, size_t size);
void *ft_memset(void *dest, int c, size_t count);
void *ft_memcpy(void *dst, const void *src, size_t n);


#endif
