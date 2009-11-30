#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libtrace.h"
#include "libpacketdump.h"

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	char ether_buf[18] = {0, };
	printf(" Ethernet:");
	if (len>=6)
		printf(" Dest: %s",trace_ether_ntoa((uint8_t *)packet, 
					ether_buf));
	else {
		printf("[|Truncated]\n");
		return;
	}
	if (len>=12) 
		printf(" Source: %s",trace_ether_ntoa((uint8_t*)(packet+6), 
					ether_buf));
	else {
		printf("[|Truncated]\n");
		return;
	}
	if (len>=14) {
		uint16_t type = htons(*(uint16_t*)(packet+12));
		printf(" Ethertype: 0x%04x\n",type);
		decode_next(packet+14,len-14,"eth",type);
	}
	else {
		printf("[|Truncated]\n");
		return;
	}
	return;
}
