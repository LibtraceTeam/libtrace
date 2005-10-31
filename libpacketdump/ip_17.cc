#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <map>
#include "libpacketdump.h"
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netdb.h>

#define STRUCT udp

#define SAFE(x) \
	((unsigned int)len>=((char*)&STRUCT->x-(char*)STRUCT+sizeof(STRUCT->x))) 
#define DISPLAY_EXP(x,fmt,exp) \
	if (SAFE(x)) \
		printf(fmt,exp); \
	else \
		return; 

#define DISPLAY(x,fmt) DISPLAY_EXP(x,fmt,STRUCT->x)

#define DISPLAYS(x,fmt) DISPLAY_EXP(x,fmt,htons(STRUCT->x))
#define DISPLAYL(x,fmt) DISPLAY_EXP(x,fmt,htonl(STRUCT->x))
#define DISPLAYIP(x,fmt) DISPLAY_EXP(x,fmt,inet_ntoa(*(struct in_addr*)&STRUCT->x))


extern "C"
void decode(int link_type,char *packet,int len)
{
	struct udphdr *udp = (struct udphdr*)packet;
	printf(" UDP:");
	if (SAFE(source)) {
		struct servent *ent=getservbyport(udp->source,"udp");
		if(ent) {
			printf(" Source %i (%s)",htons(udp->source),ent->s_name);
		} else {
			printf(" Source %i",htons(udp->source));
		}
	}
	else {
		printf("\n");
		return;
	}
	if (SAFE(dest)) {
		struct servent *ent=getservbyport(udp->dest,"udp");
		if(ent) {
			printf(" Dest %i (%s)",htons(udp->dest),ent->s_name);
		} else {
			printf(" Dest %i",htons(udp->dest));
		}
	}
	else {
		printf("\n");
		return;
	}
	printf("\n UDP:");
	DISPLAYS(len," Len %u");
	DISPLAYS(check," Checksum %u");
	printf("\n");
	if (htons(udp->source) < htons(udp->dest)) 
		decode_next(packet+sizeof(*udp),len-sizeof(*udp),"udp",htons(udp->source));
	else
		decode_next(packet+sizeof(*udp),len-sizeof(*udp),"udp",htons(udp->dest));
	return;
}
