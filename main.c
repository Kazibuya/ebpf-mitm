#include "arp.h"

int main(int argc, char **argv)
{
	t_frame	frame;
	struct sockaddr_ll	addr;
	//check_root();
	if (argc != 5)
		helper();
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
	addr.sll_ifindex = if_nametoindex("eth0");
	int res = sendto(ret, &frame, sizeof(frame), 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_ll));
	close(ret);
	if (res < 0)
		helper();
	return (0);
}
