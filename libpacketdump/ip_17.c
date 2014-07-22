#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libpacketdump.h"
#include "libtrace.h"
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netdb.h>


DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	struct libtrace_udp *udp = (struct libtrace_udp*)packet;
	printf(" UDP:");
	if (SAFE(udp, source)) {
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
	if (SAFE(udp, dest)) {
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
	DISPLAYS(udp, len," Len %u");
	DISPLAYS(udp, check," Checksum %u");
	printf("\n");
	if (htons(udp->source) < htons(udp->dest)) 
		decode_next(packet+sizeof(*udp),len-sizeof(*udp),"udp",htons(udp->source));
	else
		decode_next(packet+sizeof(*udp),len-sizeof(*udp),"udp",htons(udp->dest));
	return;
}
