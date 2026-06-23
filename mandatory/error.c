#include "arp.h"

void invalid_mac(char *str)
{
	dprintf(STDERR_FILENO, "ft_malcolm: invalid mac address: (%s)\n", str);
	exit(1);
}
void invalid_ip(char *str)
{
	dprintf(STDERR_FILENO, "ft_malcolm: unknown host or invalid IP address: (%s)\n", str);
	exit(1);
}
void	not_root()
{
	dprintf(STDERR_FILENO, "ft_malcolm: root privileges required\n");
	exit(1);
}
void	fatal_error(char *msg)
{
    perror(msg);
	if (g_sock != -1)
    	close(g_sock);
    exit(1);
}

void	helper()
{
	dprintf(STDERR_FILENO, "Usage: ./ft_malcolm <source_ip> <source_mac> <target_ip> <target_mac>\n");
	exit(1);
}
