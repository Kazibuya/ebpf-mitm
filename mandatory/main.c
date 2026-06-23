#include "arp.h"

int g_sock = -1;

static void	callback(void *ctx, void *data, char *ifname)
{
	struct sockaddr_ll addr;
	t_frame *frame = (t_frame *)ctx;
	t_frame *request = (t_frame *)data;

	printf("hook request arp\n");
	ft_memcpy(frame->header.dst, request->pkg_arp.sha, 6);
	ft_memcpy(frame->pkg_arp.tha, request->pkg_arp.sha, 6);
	ft_memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = frame->header.proto;
	addr.sll_ifindex = if_nametoindex(ifname);
	printf("envoi reply\n");
	int res = sendto(g_sock, frame, sizeof(t_frame), 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_ll));
	if (res < 0)
		fatal_error("socket");
}

static void	sigint_handler(int sig)
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

	check_root();
	if (argc != 5)
		helper();
	ft_memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigint_handler;
	sigaction(SIGINT, &sa, NULL);
	get_data(&frame, &input_arp, ifname, argv);
	g_sock = socket(AF_PACKET, SOCK_RAW, frame.header.proto);
	if (g_sock < 0)
		fatal_error("socket");
	while (1)
	{
		int ret = recvfrom(g_sock, &input_arp, sizeof(frame), 0, NULL, NULL);
		if (ret == -1)
			fatal_error("recvform");
		if (input_arp.header.proto == htons(0x0806) && input_arp.pkg_arp.oper == htons(1))
		{
			callback(&frame, &input_arp, ifname);
			break;
		}
	}
	close(g_sock);
	return (0);
}
