#include "arp.h"

void check_root()
{
	uid_t uid;

	uid = getuid();
	if (uid != 0)
		not_root();
}
