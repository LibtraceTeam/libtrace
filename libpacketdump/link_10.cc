#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <map>
#include "libpacketdump.h"
#include "libtrace.h"

extern "C"
void decode(int link_type,char *packet,int len)
{
	// ATM
	printf(" Legacy Framing:");
	if (len>=12) {
		uint16_t type = htons(*(uint16_t*)(packet+sizeof(libtrace_atm_cell)+4));
		printf(" %04x\n",type);
		decode_next(packet+sizeof(libtrace_atm_cell) + 4,
				len-sizeof(libtrace_atm_cell) -4, 
				"eth",type);
	}
	else {
		printf("[|Truncated]\n");
		return;
	}
	return;
}
