#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include "libpacketdump.h"

typedef struct gre_t {
	uint16_t flags;
	uint16_t ethertype;
	uint16_t checksum;
	uint16_t reserved1;
} gre_t;

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	// GRE
	if (len<2) {
		printf(" GRE: [Truncated]\n");
		return;
	}
	printf(" GRE: %s\n",
		ntohs(((gre_t*)packet)->flags) & 0x8000 
			? "Checksum present"
			: "Checksum absent");
	printf(" GRE: Version: %d\n", ntohs(((gre_t*)packet)->flags) & 0x0007);
	printf(" GRE: Protocol: %04x\n", ntohs(((gre_t*)packet)->ethertype));

	if (ntohs(((gre_t*)packet)->flags) & 0x8000) {
		decode_next(packet+4,len-4,"link",
				ntohs(((gre_t*)packet)->ethertype));
	}
	else {
		decode_next(packet+8,len-8,"link",
				ntohs(((gre_t*)packet)->ethertype));
	}
	return;
}
