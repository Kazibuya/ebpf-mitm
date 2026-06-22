#include "arp.h"
#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <net/if.h>
#include <stdio.h>

struct bpf_link *g_link;

void load_hook()
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	obj = bpf_object__open("xdp_prog.o");
	if (!obj)
	{
		perror("bpf_object__open");
		exit (1);
	}
	if (bpf_object__load(obj))
	{
		bpf_object__close(obj);
		perror("bpf_object__load");
		exit(1);
	}
	prog = bpf_object__find_program_by_name(obj, "xdp_prog");
	if (!prog)
	{
		bpf_object__close(obj);
		perror("bpf_object__find_program_by_name");
		exit(1);
	}
	g_link = bpf_program__attach_xdp(prog, if_nametoindex("enp0s3"));
	if (!g_link)
	{
		bpf_object__close(obj);
		perror("bpf_program__attach_xdp");
		exit(1);
	}
	bpf_object__close(obj);
}

int main(int argc, char **argv)
{
	t_frame	frame;
	struct sockaddr_ll	addr;
	check_root();
	if (argc != 5)
		helper();
	load_hook();
	memset(&frame, 0, sizeof(frame));
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

	int ret = socket(AF_PACKET, SOCK_RAW, frame.header.proto);
	if (ret < 0)
		helper();
	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = frame.header.proto;
	addr.sll_ifindex = if_nametoindex("enp0s3");
	int res = sendto(ret, &frame, sizeof(frame), 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_ll));
	close(ret);
	if (res < 0)
	{
		perror("socket");
		helper();
	}
	return (0);
}
