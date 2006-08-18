#include "libpacketdump.h"

void decode(int link_type,char *packet,int len)
{
	decode_next(packet,len,"eth",2048);
	return;
}
