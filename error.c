#include "arp.h"

void invalid_mac(char *str)
{
	dprintf(STDERR_FILENO, "ft_malcolm: invalid mac address: %s\n", str);
	exit(1);
}
void invalid_ip(char *str)
{
	dprintf(STDERR_FILENO, "ft_malcolm: unknown host or invalid IP address: %s\n", str);
	exit(1);
}
void	not_root()
{
	dprintf(STDERR_FILENO, "ft_malcolm: root privileges required\n");
	exit(1);
}
void invalid_inputs()
{
	dprintf(STDERR_FILENO, "ft_malcolm: invalid input need MAC\n");
	exit(1);
}
void	helper()
{
	dprintf(STDERR_FILENO, "ft_malcolm: write usage here\n");
	exit(1);
}
