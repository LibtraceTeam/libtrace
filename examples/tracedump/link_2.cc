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
	printf(" Ethernet:");
	if (len>=6)
		printf(" %s",ether_ntoa((struct ether_addr*)packet));
	else {
		printf("[|Truncated]\n");
		return;
	}
	if (len>=12) 
		printf(" %s",ether_ntoa((struct ether_addr*)(packet+6)));
	else {
		printf("[|Truncated]\n");
		return;
	}
	if (len>=14) {
		uint16_t type = htons(*(uint16_t*)(packet+12));
		printf(" %04x\n",type);
		decode_next(packet+14,len-14,"eth",type);
	}
	else {
		printf("[|Truncated]\n");
		return;
	}
	return;
}
