#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

static void	not_root()
{
	dprintf(STDERR_FILENO, "ft_malcolm: root privileges required\n");
	exit(1);
}

static void	helper()
{
	dprintf(STDERR_FILENO, "ft_malcolm: write usage here\n");
	exit(1);
}

int main(int argc, char **argv)
{
	uid_t uid;

	(void)argv;
	uid = getuid();
	if (uid != 0)
		not_root();
	if (argc != 2)
		helper();
	return 0;
}
