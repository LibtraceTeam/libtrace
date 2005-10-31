#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <map>
#include "libpacketdump.h"

extern "C"
void decode(int link_type,char *packet,int len)
{
	printf(" Legacy Framing: ");
	if (len>=10) {
		decode_next(packet+10,len-10,"link",2);
	}
	else {
		printf("[|Truncated]\n");
		return;
	}
	return;
}
