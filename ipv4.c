#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

static void invalid_ip(char *str)
{
	dprintf(STDERR_FILENO, "ft_malcolm: unknown host or invalid IP address: %s\n", str);
	exit(1);
}

static void invalid_inputs()
{
	dprintf(STDERR_FILENO, "ft_malcolm: invalid input need MAC\n");
	exit(1);
}
int main(int argc, char **argv)
{
	int ret = 0;
	struct in_addr dst;
	if (argc != 2)
		invalid_inputs();

	ret = inet_pton(AF_INET, argv[1], &dst);
	if (ret != 1)
		invalid_ip(argv[1]);
	printf("%x\n", htonl(dst.s_addr));
	return 0;
}
