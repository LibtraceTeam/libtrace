/* DCCP */
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libpacketdump.h"
#include <netinet/tcp.h>
#include <netinet/in.h>

#define STRUCT dccp

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

struct dccphdr {
	uint16_t source;
	uint16_t dest;
	uint8_t type:4;
	uint8_t ccval:4;
	uint32_t seq:24;
	uint8_t doff;
	uint8_t ndp:4;
	uint8_t cslen:4;
	uint16_t check;
};

static char *dccp_types[]={
	"DCCP-Request packet",
	"DCCP-Response packet",
	"DCCP-Data packet",
	"DCCP-Ack packet",
	"DCCP-DataAck packet",
	"DCCP-CloseReq packet",
	"DCCP-Close packet",
	"DCCP-Reset packet",
	"DCCP-Move packet",
	};

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	struct dccphdr *dccp = (struct dccphdr*)packet;
	DISPLAYS(source," DCCP: Source %i");
	DISPLAYS(dest," Dest %i");
	if (len>4) {
		printf("\n DCCP: Type %i",dccp->type);
		if (dccp->type<sizeof(dccp_types)) {
			printf(" (%s)\n",dccp_types[dccp->type]);
		} else {
			printf(" (Unknown)\n");
		}
		printf(" DCCP: CcVal %i\n",dccp->ccval);
	}
	else  {
		printf("\n"); 
		return;
	}
	if (len>7)
		printf(" DCCP: Seq %u\n",dccp->seq); // htonwhat?
	else
		return;
	DISPLAY(doff," DCCP: Dataoff: %i\n");
	if (len>9)
		printf(" DCCP: NDP %i CsLen: %i\n",dccp->ndp,dccp->cslen);
	else {
		return;
	}
	DISPLAY(check," DCCP: Checksum: %i\n");
	if (htons(dccp->source) < htons(dccp->dest)) 
		decode_next(packet+dccp->doff*4,len-dccp->doff*4,"dccp",htons(dccp->source));
	else
		decode_next(packet+dccp->doff*4,len-dccp->doff*4,"dccp",htons(dccp->dest));
	return;
}
