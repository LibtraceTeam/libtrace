#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include "libpacketdump.h"
#include "libtrace.h"

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	// ATM
	printf(" Legacy Framing:");
	if (len>=12) {
		uint16_t type = htons(*(uint16_t*)(packet+sizeof(libtrace_atm_cell_t)+4));
		printf(" %04x\n",type);
		decode_next(packet+sizeof(libtrace_atm_cell_t) + 4,
				len-sizeof(libtrace_atm_cell_t) -4, 
				"eth",type);
	}
	else {
		printf("[|Truncated]\n");
		return;
	}
	return;
}
