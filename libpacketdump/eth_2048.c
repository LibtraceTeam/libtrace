#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "libpacketdump.h"
#ifndef WIN32
	#include <netinet/in_systm.h>
#endif
#include <arpa/inet.h>
#include <netdb.h>

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	libtrace_ip_t *ip = (libtrace_ip_t*)packet;
	if (len>=1) {
		printf(" IP: Header Len %i",ip->ip_hl*4);
		printf(" Ver %i",ip->ip_v);
	}
	//DISPLAY(ip_tos," TOS %02x")
	DISPLAY_EXP(ip, ip_tos," DSCP %02x",ip->ip_tos >> 2);
	DISPLAY_EXP(ip, ip_tos," ECN %x",ip->ip_tos & 0x2);
	DISPLAYS(ip, ip_len," Total Length %i");
	printf("\n IP:");
	DISPLAYS(ip, ip_id," Id %u");
	
	if ((unsigned int)len >= ((char *)&ip->ip_ttl - (char *)ip - 2)) {
		printf(" Fragoff %i", ntohs(ip->ip_off) & 0x1FFF);
		if (ntohs(ip->ip_off) & 0x2000) printf(" MORE_FRAG");
		if (ntohs(ip->ip_off) & 0x4000) printf(" DONT_FRAG");
		if (ntohs(ip->ip_off) & 0x8000) printf(" RESV_FRAG");
	}
	//printf("\n IP:");
	DISPLAY(ip, ip_ttl,"\n IP: TTL %i");
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
	DISPLAYS(ip, ip_sum," Checksum %i\n");
	DISPLAYIP(ip, ip_src," IP: Source %s ");
	DISPLAYIP(ip, ip_dst,"Destination %s\n");
	decode_next(packet+ip->ip_hl*4,len-ip->ip_hl*4,"ip",ip->ip_p);
	return;
}
