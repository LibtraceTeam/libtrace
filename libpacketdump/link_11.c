#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libpacketdump.h"

void decode(int link_type,char *packet,int len)
{
	// Ethernet - just raw ethernet frames
	printf(" Legacy: ");
	if (len>=10) {
		decode_next(packet,len,"link",2);
	}
	else {
		printf("[|Truncated]\n");
		return;
	}
	return;
}
