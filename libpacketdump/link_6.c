/* 
 * Linux SLL Decoder 
 * 
 */

#include "config.h"
#include "libtrace_int.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include "libpacketdump.h"
#include "libtrace.h"

#include "arphrd.h"

DLLEXPORT void decode(int link_type ,const char *pkt,unsigned len) 
{
	libtrace_sll_header_t *sll = (libtrace_sll_header_t *) pkt;
	libtrace_linktype_t linktype = link_type;
	void *ret;	

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
	ret=trace_get_payload_from_meta(pkt, &linktype, &len);
	
	if (ntohs(sll->hatype) == ARPHRD_ETHER || 
				ntohs(sll->hatype) == ARPHRD_LOOPBACK) 
		decode_next(pkt + sizeof(*sll), len - sizeof(*sll), "eth", ntohs(sll->protocol));
	
	else
		decode_next(ret, len, "link", ntohs(sll->hatype));

	return;
	
}


