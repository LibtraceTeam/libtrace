#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include "libpacketdump.h"
#include "libtrace.h"

DLLEXPORT void decode(int link_type UNUSED, const char *packet, unsigned len)
{
	libtrace_ip6_frag_t *frag = (libtrace_ip6_frag_t *)packet;
	uint16_t offset;

	// IPv6 Fragment Header
	if (len == 0) {
		printf(" IPv6 Frag: [Truncated]\n");
		return;
	}

	

	printf(" IPv6 Frag: Next Header: %u\n", frag->nxt);
	
	offset = ntohs(frag->frag_off);
	printf(" IPv6 Frag: Offset: %u", offset & 0xFFF8);
	if ((offset & 0x1)) printf(" MORE_FRAG");
	
	printf("\n"); 
	printf(" IPv6 Frag: Identification: %u\n", ntohl(frag->ident));

	/* Only dump the next header if this is the first fragment */
	if ((offset & 0xFFF8) != 0)
		return;

	decode_next(packet + sizeof(libtrace_ip6_frag_t), 
			len - sizeof(libtrace_ip6_frag_t), "ip", frag->nxt);
	return;	

}
