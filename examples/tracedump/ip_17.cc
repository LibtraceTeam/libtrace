#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
#include <map>
#include "tracedump.h"
#include <netinet/udp.h>
#include <netinet/in.h>

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
	DISPLAYS(source," Source %i")
	DISPLAYS(dest," Dest %i")
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
