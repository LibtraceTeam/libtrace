#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <map>
#include "libpacketdump.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>

#define DISPLAY_EXP(x,fmt,exp) \
	if ((unsigned int)len>=((char*)&ip->x-(char*)ip+sizeof(ip->x))) \
		printf(fmt,exp); \
	else \
		return; 

#define DISPLAY(x,fmt) DISPLAY_EXP(x,fmt,ip->x)

#define DISPLAYS(x,fmt) DISPLAY_EXP(x,fmt,htons(ip->x))
#define DISPLAYIP(x,fmt) DISPLAY_EXP(x,fmt,inet_ntoa(*(struct in_addr*)&ip->x))

extern "C"
void decode(int link_type,char *packet,int len)
{
	struct iphdr *ip = (struct iphdr*)packet;
	if (len>=1) {
		printf(" IP: Header Len %i",ip->ihl*4);
		printf(" Ver %i",ip->version);
	}
	DISPLAY(tos," TOS %02x")
	DISPLAYS(tot_len," Total Length %i")
	printf("\n IP:");
	DISPLAY(id," Id %i");
	DISPLAY(frag_off," Fragoff %i");
	//printf("\n IP:");
	DISPLAY(ttl," TTL %i");
	if ((unsigned int)len>=((char*)&ip->protocol-(char*)ip+sizeof(ip->protocol))) {
		struct protoent *ent=getprotobynumber(ip->protocol);
		if (ent) {
			printf(" Proto %i (%s)",ip->protocol,ent->p_name);
		}
		else {
			printf(" Proto %i",ip->protocol);
		}
	} else {
		printf("\n");
		return;
	}
	DISPLAYS(check," Checksum %i\n");
	DISPLAYIP(saddr," IP: Source %s ");
	DISPLAYIP(daddr,"Destination %s\n");
	decode_next(packet+sizeof(*ip),len-sizeof(*ip),"ip",ip->protocol);
	return;
}
