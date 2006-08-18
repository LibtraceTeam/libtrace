#include "libpacketdump.h"
#include "libtrace.h"
#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>

void decode(int link_type,char *packet,int len)
{
	// POS
	printf(" Legacy POS Framing:");
	// take into account llc
	if (len>=4) {
		uint16_t type = htons(
				((libtrace_pos_t *)packet)->ether_type);
		printf(" %04x\n",type);
		decode_next(packet+sizeof(libtrace_pos_t),
				len-sizeof(libtrace_pos_t),
				"eth",type);
	}
	else {
		printf("[|Truncated]\n");
		return;
	}
	return;
}
