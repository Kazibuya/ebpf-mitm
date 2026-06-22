#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

static void invalid_mac(char *str)
{
	dprintf(STDERR_FILENO, "ft_malcolm: invalid mac address: %s\n", str);
	exit(1);
}

static void invalid_inputs()
{
	dprintf(STDERR_FILENO, "ft_malcolm: invalid input need MAC\n");
	exit(1);
}

int main(int argc, char **argv)
{
	if (argc != 2)
		invalid_inputs();
	u_int8_t mac[6];
	unsigned int tmp[6];
	int valided_zone = 0;
	int	len = 0;

	valided_zone = sscanf(argv[1], "%x:%x:%x:%x:%x:%x%n", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5], &len);
	if (valided_zone != 6 || len != (int)strlen(argv[1]))
		invalid_mac(argv[1]);
	for (int i = 0; i < 6 ; ++i)
	{
		if (tmp[i] > 255)
			invalid_mac(argv[1]);
		mac[i] = tmp[i];
	}
	printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return 0;
}

