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
	printf(" Legacy POS:");
	if (len>=4) {
		uint16_t type = htons(*(uint16_t*)(packet+2));
		printf(" %04x\n",type);
		decode_next(packet+4,len-4,"eth",type);
	}
	else {
		printf("[|Truncated]\n");
		return;
	}
	return;
}
