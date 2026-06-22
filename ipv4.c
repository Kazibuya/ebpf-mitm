#include "arp.h"

void get_ipv4(char *str, t_frame *frame, bool who)
{
	int ret = 0;
	struct in_addr dst;

	ret = inet_pton(AF_INET, str, &dst);
	if (ret != 1)
		invalid_ip(str);
	if (who)
		frame->pkg_arp.spa = dst.s_addr;
	else
		frame->pkg_arp.tpa = dst.s_addr;
}
