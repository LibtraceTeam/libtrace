#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
#include <map>
#include "tracedump.h"
#include <netinet/ip_icmp.h>
#include <netinet/in.h>

#define STRUCT icmp

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

static char *unreach_types[]={
	"Destination Network Unreachable",
	"Destination Host Unreachable",
	"Destination Protocol Unreachable",
	"Destination Port Unreachable",
	"Fragmentation Required And Dont Fragment Set",
	"Source Route Failed",
	"Destination Network Unknown",
	"Destination Host Unknown",
	"Source Host Isolated",
	"Destination Network Administratively Prohibited",
	"Destination Host Administratively Prohibited",
	"Destination Network Unreachable For Type Of Service",
	"Destination Host Unreachable For Type Of Service",
	"Communication Administratively Prohibited",
	"Host Precedence Violation",
	"Precedence Cutoff In Effect",
};

extern "C"
void decode(int link_type,char *packet,int len)
{
	struct icmphdr *icmp = (struct icmphdr*)packet;
	if (len<1)
		return;
	printf(" ICMP:");
	switch(icmp->type) {
		case 0:
			printf(" Type: 0 (ICMP Echo Reply)\n");
			break;
		case 3:
			printf(" Type: 3 (ICMP Destination Unreachable)\n");
			if (len<2)
				return;
			if (icmp->code<sizeof(unreach_types)) {
				printf(" ICMP: Code: %i (%s)\n",icmp->code,
						unreach_types[icmp->code]);
			}
			else {
				printf(" ICMP: Code: %i (Unknown)\n",icmp->code);
			}
			// Pretend that this was just passed up from ethernet
			decode_next(packet+8,len-8,
					"eth",0x0800);

			break;
		case 8:
			printf(" Type: 8 (ICMP Echo Request)\n");
			break;
		default:
			printf(" Type: %i (Unknown)\n",icmp->type);
			break;

	}
	return;
}
