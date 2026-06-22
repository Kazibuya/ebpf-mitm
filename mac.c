#include "arp.h"

void get_mac(char *str, t_frame *frame, bool who)
{
	unsigned int tmp[6];
	int valided_zone = 0;
	int	len = 0;

	valided_zone = sscanf(str, "%x:%x:%x:%x:%x:%x%n", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5], &len);
	if (valided_zone != 6 || len != (int)strlen(str))
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
