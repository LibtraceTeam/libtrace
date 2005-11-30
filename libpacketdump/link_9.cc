#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <map>
#include "libpacketdump.h"

extern "C"
void decode(int link_type,char *packet,int len)
{
	// POS
	printf(" Legacy Framing:");
	// take into account llc
	if (len>=4) {
		uint16_t type = htons(
				((libtrace_pos *)packet)->ether_type);
		printf(" %04x\n",type);
		decode_next(packet+sizeof(libtrace_pos),
				len-sizeof(libtrace_pos),
				"eth",type);
	}
	else {
		printf("[|Truncated]\n");
		return;
	}
	return;
}
