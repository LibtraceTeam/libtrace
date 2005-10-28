#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <map>
#include "tracedump.h"

extern "C"
void decode(int link_type,char *packet,int len)
{
	printf(" Legacy Framing: ");
	decode_next(packet,len,"link",2);
	return;
}
