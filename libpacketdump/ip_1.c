#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libpacketdump.h"

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

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	libtrace_icmp_t *icmp = (libtrace_icmp_t*)packet;
	if (len<1)
		return;
	printf(" ICMP:");
	switch(icmp->type) {
		case 0:
			printf(" Type: 0 (ICMP Echo Reply) Sequence: ");
			if (len < 4)
				printf("(Truncated)\n");
			else
				printf("%u\n", ntohs(icmp->un.echo.sequence));
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
			printf(" Type: 8 (ICMP Echo Request) Sequence: ");
			if (len < 4)
				printf("(Truncated)\n");
			else
				printf("%u\n", ntohs(icmp->un.echo.sequence));
			break;
		case 11:
			printf(" Type: 11 (ICMP TTL Exceeded)\n");
			decode_next(packet+8,len-8,
					"eth",0x0800);
			break;
		default:
			printf(" Type: %i (Unknown)\n",icmp->type);
			break;

	}
	printf(" ICMP: Checksum: ");
	if (len < 8)
		printf("(Truncated)\n");
	else
		printf("%u\n", ntohs(icmp->checksum));


	return;
}
