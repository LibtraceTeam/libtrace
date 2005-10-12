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
	printf(" Legacy ATM:");
	/*
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
	*/
	if (len>=24) {
		uint16_t type = htons(*(uint16_t*)(packet+22));
		printf(" %04x\n",type);
		decode_next(packet+24,len-24,"eth",type);
	}
	else {
		printf("[|Truncated]\n");
		return;
	}
	return;
}
