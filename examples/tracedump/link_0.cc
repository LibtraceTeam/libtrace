#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <map>
#include "tracedump.h"

extern "C"
void decode(int link_type,char *packet,int len)
{
	printf(" Legacy PoS:");
	if (len>=4)
		printf(" %08x\n",*(uint32_t *)packet);
	else {
		printf("[|Truncated]\n");
		return;
	}
	if (len>4) {
		decode_next(packet+4,len-4,"eth",2048);
	}
	else {
		printf("[|Truncated]\n");
		return;
	}
	return;
}
