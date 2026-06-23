#include "arp.h"

void	get_data(t_frame *frame, t_frame *input_arp, char *ifname, char **argv)
{
	ft_memset(frame, 0, sizeof(t_frame));
	ft_memset(input_arp, 0, sizeof(t_frame));
	get_ifname(ifname);
	get_ipv4(argv[1], frame, true);
	get_ipv4(argv[3], frame, false);
	get_mac(argv[2], frame, true);
	get_mac(argv[4], frame, false);
	frame->header.proto = htons(0x0806);
	frame->pkg_arp.hlen = 6;
	frame->pkg_arp.htype = htons(1);
	frame->pkg_arp.oper = htons(2);
	frame->pkg_arp.plen = 4;
	frame->pkg_arp.ptype = htons(0x0800);

}

void	get_ifname(char *ifname)
{
	struct ifaddrs *ifap;

	if (getifaddrs(&ifap) == -1)
		fatal_error("getifaddrs");
	for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
	{
		if ((ifa->ifa_flags & IFF_UP) 
				&& !(ifa->ifa_flags & IFF_LOOPBACK) 
				&& ifa->ifa_addr 
				&& ifa->ifa_addr->sa_family == AF_INET)
		{
			ft_strlcpy(ifname, ifa->ifa_name, IF_NAMESIZE);
			break;
		}
	}
	if (ifname[0] == '\0')
		fatal_error("ifname");
	freeifaddrs(ifap);
}

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

void get_mac(char *str, t_frame *frame, bool who)
{
	unsigned int tmp[6];
	int valided_zone = 0;
	int	len = 0;

	valided_zone = sscanf(str, "%x:%x:%x:%x:%x:%x%n", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5], &len);
	if (valided_zone != 6 || len != (int)ft_strlen(str))
		invalid_mac(str);
	for (int i = 0; i < 6 ; ++i)
	{
		if (tmp[i] > 255)
			invalid_mac(str);
		if (who)
		{
			frame->header.src[i] = tmp[i];
			frame->pkg_arp.sha[i] = tmp[i];
		}
		else
		{
			frame->header.dst[i] = tmp[i];
			frame->pkg_arp.tha[i] = tmp[i];
		}
	}
}

void check_root()
{
	uid_t uid;

	uid = getuid();
	if (uid != 0)
		not_root();
}
