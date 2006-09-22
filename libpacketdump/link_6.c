/* 
 * Linux SLL Decoder 
 * 
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include "libpacketdump.h"
#include "libtrace.h"
#include "libtrace_int.h"

void decode(int link_type, char *pkt, int len) 
{
	libtrace_sll_header_t *sll = (libtrace_sll_header_t *) pkt;
	uint16_t type;
	
	if (len < sizeof(*sll)) {
		printf(" Linux SLL: Truncated (len = %u)\n", len);
		return;
	}

	printf(" Linux SLL: Packet Type = ");
	switch(ntohs(sll->pkttype)) {
		case TRACE_SLL_HOST: printf("HOST\n"); break;
		case TRACE_SLL_BROADCAST: printf("BROADCAST\n"); break;
		case TRACE_SLL_MULTICAST: printf("MULTICAST\n"); break;
		case TRACE_SLL_OTHERHOST: printf("OTHERHOST\n"); break;
		case TRACE_SLL_OUTGOING: printf("OUTGOING\n"); break;
		default: printf("Unknown (0x%04x)\n", ntohs(sll->pkttype));
	}
	
	printf(" Linux SLL: Hardware Address Type = 0x%04x\n", ntohs(sll->hatype));
	printf(" Linux SLL: Hardware Address Length = %u\n", ntohs(sll->halen));
	printf(" Linux SLL: Hardware Address = %s\n", trace_ether_ntoa( (sll->addr), NULL));

	printf(" Linux SLL: Protocol = 0x%04x\n", ntohs(sll->protocol));

	/* Decide how to continue processing... */
	
	/* Do we recognise the hardware address type? */
	type = arphrd_type_to_libtrace(ntohs(sll->hatype));
	if (type != 65535) { 
		decode_next(pkt + sizeof(*sll), len - sizeof(*sll), "link", type);
		return;
	}

	/* Meh.. pass it off to eth decoder */
	decode_next(pkt + sizeof(*sll), len - sizeof(*sll), "eth", ntohs(sll->protocol));

}


