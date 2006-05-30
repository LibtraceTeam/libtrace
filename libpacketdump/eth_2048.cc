#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libpacketdump.h"
#include <sys/socket.h>
#ifndef WIN32
	#include <netinet/in_systm.h>
#endif
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
	libtrace_ip_t *ip = (libtrace_ip_t*)packet;
	if (len>=1) {
		printf(" IP: Header Len %i",ip->ip_hl*4);
		printf(" Ver %i",ip->ip_v);
	}
	DISPLAY(ip_tos," TOS %02x")
	DISPLAYS(ip_len," Total Length %i")
	printf("\n IP:");
	DISPLAY(ip_id," Id %u");
	
	if ((unsigned int)len >= ((char *)&ip->ip_ttl - (char *)ip - 2)) {
		printf(" \n Fragoff %i", ip->ip_off);
		if (ip->ip_mf) printf(" MORE_FRAG");
		if (ip->ip_df) printf(" DONT_FRAG");
		if (ip->ip_rf) printf(" RESV_FRAG");
	}
	//printf("\n IP:");
	DISPLAY(ip_ttl,"\n TTL %i");
	if ((unsigned int)len>=((char*)&ip->ip_p-(char*)ip+sizeof(ip->ip_p))) {
		struct protoent *ent=getprotobynumber(ip->ip_p);
		if (ent) {
			printf(" Proto %i (%s)",ip->ip_p,ent->p_name);
		}
		else {
			printf(" Proto %i",ip->ip_p);
		}
	} else {
		printf("\n");
		return;
	}
	DISPLAYS(ip_sum," Checksum %i\n");
	DISPLAYIP(ip_src," IP: Source %s ");
	DISPLAYIP(ip_dst,"Destination %s\n");
	decode_next(packet+sizeof(*ip),len-sizeof(*ip),"ip",ip->ip_p);
	return;
}
