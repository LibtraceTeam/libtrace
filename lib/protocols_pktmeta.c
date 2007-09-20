/* Protocol decodes for packet metadata headers */
#include "libtrace.h"
#include "libtrace_int.h"
#include "protocols.h"
#include <assert.h>

#ifndef WIN32
#include <net/if_arp.h>
#endif

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER    1               /* Ethernet 10/100Mbps.  */
#endif

#ifndef ARPHRD_PPP
#define ARPHRD_PPP      512
#endif

/* NB: type is returned as an ARPHRD_ type for SLL*/
void *trace_get_payload_from_linux_sll(const void *link,
		uint16_t *type, uint32_t *remaining) 
{
	libtrace_sll_header_t *sll;

	sll = (libtrace_sll_header_t*) link;

	if (remaining) {
		if (*remaining < sizeof(*sll))
			return NULL;
		*remaining-=sizeof(*sll);
	}

	if (type) *type = ntohs(sll->hatype);

	return (void*)((char*)sll+sizeof(*sll));

}

/* NB: type is returned as an ethertype */
static void *trace_get_payload_from_pflog(const void *link,
		libtrace_linktype_t *type, uint32_t *remaining)
{
	libtrace_pflog_header_t *pflog = (libtrace_pflog_header_t*)link;
	if (remaining) {
		if (*remaining<sizeof(*pflog)) 
			return NULL;
		*remaining-=sizeof(*pflog);
	}
	if (type) {
		*type = TRACE_TYPE_NONE;
	}
	return (void*)((char*)pflog+ sizeof(*pflog));
}

/* Returns the 'payload' of the prism header, which is the 802.11 frame */
static void *trace_get_payload_from_prism (const void *link,
		libtrace_linktype_t *type, uint32_t *remaining)
{
	if (remaining) {
		if (*remaining<144) 
			return NULL;
		*remaining-=144;
	}

	if (type) *type = TRACE_TYPE_80211;

	return (void *) ((char*)link+144);
}

/* Returns the 'payload' of the radiotap header, which is the 802.11 frame */
static void *trace_get_payload_from_radiotap (const void *link, 
		libtrace_linktype_t *type, uint32_t *remaining)
{
	struct libtrace_radiotap_t *rtap = (struct libtrace_radiotap_t*)link;
	uint16_t rtaplen = bswap_le_to_host16(rtap->it_len);
	if (remaining) {
		if (*remaining < rtaplen)
			return NULL;
		*remaining -= rtaplen;
	}

	if (type) *type = TRACE_TYPE_80211;

	return (void*) ((char*)link + rtaplen);
}

DLLEXPORT void *trace_get_packet_meta(const libtrace_packet_t *packet, 
		libtrace_linktype_t *linktype,
		uint32_t *remaining)
{
	uint32_t dummyrem;

	assert(packet != NULL);
	assert(linktype != NULL);
	
	if (remaining == NULL) 
		remaining = &dummyrem;
	
	void *pktbuf = trace_get_packet_buffer(packet, linktype, remaining);
	switch (*linktype) {
		case TRACE_TYPE_LINUX_SLL:
		case TRACE_TYPE_80211_RADIO:
		case TRACE_TYPE_80211_PRISM:
			return pktbuf;
		/* Non metadata packets */
		case TRACE_TYPE_HDLC_POS:
		case TRACE_TYPE_ETH:
		case TRACE_TYPE_ATM:
		case TRACE_TYPE_80211:
		case TRACE_TYPE_NONE:
		case TRACE_TYPE_PFLOG:
		case TRACE_TYPE_POS:
		case TRACE_TYPE_AAL5:
		case TRACE_TYPE_DUCK:
		case TRACE_TYPE_LLCSNAP:
		case TRACE_TYPE_PPP:
		case TRACE_TYPE_METADATA:
			return NULL;
	}

	/* Shouldn't get here */
	return NULL;
}

DLLEXPORT void *trace_get_payload_from_meta(const void *meta,
		libtrace_linktype_t *linktype,
		uint32_t *remaining)
{
	void *nexthdr; 
	uint16_t arphrd;
	
	assert(meta != NULL);
	assert(linktype != NULL);
	assert(remaining != NULL);
	
	switch(*linktype) {
		case TRACE_TYPE_LINUX_SLL:
			nexthdr = trace_get_payload_from_linux_sll(meta,
					&arphrd, remaining);
			*linktype = arphrd_type_to_libtrace(arphrd);
			return nexthdr;
		case TRACE_TYPE_80211_RADIO:
			nexthdr = trace_get_payload_from_radiotap(meta,
					linktype, remaining);
			return nexthdr;
		case TRACE_TYPE_80211_PRISM:
			nexthdr = trace_get_payload_from_prism(meta,
					linktype, remaining);
			return nexthdr;
		case TRACE_TYPE_PFLOG:
			nexthdr = trace_get_payload_from_pflog(meta,
					linktype, remaining);
			return nexthdr;
		case TRACE_TYPE_HDLC_POS:
		case TRACE_TYPE_ETH:
		case TRACE_TYPE_ATM:
		case TRACE_TYPE_80211:
		case TRACE_TYPE_NONE:
		case TRACE_TYPE_POS:
		case TRACE_TYPE_AAL5:
		case TRACE_TYPE_DUCK:
		case TRACE_TYPE_LLCSNAP:
		case TRACE_TYPE_PPP:
		case TRACE_TYPE_METADATA:
			/* In this case, the pointer passed in does not point
			 * to a metadata header and so we cannot get the
			 * payload.
			 */
			return NULL;
	}
	/* Shouldn't get here */
	return NULL;
}

/* Take a pointer to the start of an IEEE 802.11 MAC frame and return a pointer
 * to the source MAC address.  
 * If the frame does not contain a sender address, e.g. ACK frame, return NULL.
 * If the frame is a 4-address WDS frame, return TA, i.e. addr2.
 * NB: This function decodes the 802.11 header, so it assumes that there are no
 * bit-errors. If there are, all bets are off.
 */
static
uint8_t *get_source_mac_from_wifi(void *wifi) {
	if (wifi == NULL) return NULL;
	struct libtrace_80211_t *w = (struct libtrace_80211_t *) wifi;
	
	/* If the frame is of type CTRL */
	if (w->type == 0x1) 
		/* If bit 2 of the subtype field is zero, this indicates that
		 * there is no transmitter address, i.e. the frame is either an
		 * ACK or a CTS frame */
		if ((w->subtype & 0x2) == 0)
			return NULL;

	/* Always return the address of the transmitter, i.e. address 2 */
	return (uint8_t *) &w->mac2;
}

DLLEXPORT uint8_t *trace_get_source_mac(libtrace_packet_t *packet) {
	void *link;
	uint32_t remaining;
	libtrace_linktype_t linktype;
	assert(packet);
	link = trace_get_layer2(packet,&linktype,&remaining);

	if (!link)
		return NULL;
	
	switch (linktype) {
		case TRACE_TYPE_ETH:
			return (uint8_t *)&(((libtrace_ether_t*)link)->ether_shost);
		case TRACE_TYPE_80211:
			return get_source_mac_from_wifi(link);
		/* These packets don't have MAC addresses */
		case TRACE_TYPE_POS:
		case TRACE_TYPE_NONE:
		case TRACE_TYPE_HDLC_POS:
		case TRACE_TYPE_PFLOG:
		case TRACE_TYPE_ATM:
		case TRACE_TYPE_DUCK:
		case TRACE_TYPE_METADATA:
		case TRACE_TYPE_AAL5:
		case TRACE_TYPE_LLCSNAP:
		case TRACE_TYPE_PPP:
			return NULL;

		/* Metadata headers should already be skipped */
		case TRACE_TYPE_LINUX_SLL:
		case TRACE_TYPE_80211_PRISM:
		case TRACE_TYPE_80211_RADIO:
			assert(!"Metadata headers should already be skipped");
			break;
	}
	fprintf(stderr,"%s not implemented for linktype %i\n", __func__, linktype);
	assert(0);
	return NULL;
}

DLLEXPORT uint8_t *trace_get_destination_mac(libtrace_packet_t *packet) 
{
	void *link;
	libtrace_linktype_t linktype;
	uint32_t remaining;

	link = trace_get_layer2(packet,&linktype,&remaining);

	libtrace_80211_t *wifi;
        libtrace_ether_t *ethptr = (libtrace_ether_t*)link;


	if (!link)
		return NULL;

	switch (linktype) {
		case TRACE_TYPE_80211:
			wifi=(libtrace_80211_t*)link;
			return (uint8_t*)&wifi->mac1;
		case TRACE_TYPE_80211_RADIO:
			wifi=(libtrace_80211_t*)trace_get_payload_from_radiotap(
					link,NULL,NULL);
			return (uint8_t*)&wifi->mac1;
		case TRACE_TYPE_80211_PRISM:
			wifi=(libtrace_80211_t*)((char*)link+144);
			return (uint8_t*)&wifi->mac1;
		case TRACE_TYPE_ETH:
			return (uint8_t*)&ethptr->ether_dhost;
		case TRACE_TYPE_POS:
		case TRACE_TYPE_NONE:
		case TRACE_TYPE_ATM:
		case TRACE_TYPE_HDLC_POS:
		case TRACE_TYPE_LINUX_SLL:
		case TRACE_TYPE_PFLOG:
		case TRACE_TYPE_DUCK:
		case TRACE_TYPE_METADATA:
			/* No MAC address */
			return NULL;
		default:
			break;
	}
	fprintf(stderr,"Not implemented\n");
	assert(0);
	return NULL;
}


