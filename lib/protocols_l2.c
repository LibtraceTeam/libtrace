/* Protocol decodes for layer 2 */
#include "libtrace.h"
#include "protocols.h"
#include "libtrace_int.h"
#include <assert.h>

/* Returns the payload from 802.3 ethernet.  Type optionally returned in
 * "type" in host byte order.  This will return a vlan header.
 */
void *trace_get_payload_from_ethernet(void *ethernet, 
		uint16_t *type,
		uint32_t *remaining)
{
	libtrace_ether_t *eth = (libtrace_ether_t*)ethernet;

	if (remaining) {
		if (*remaining < sizeof(*eth))
			return NULL;
		*remaining-=sizeof(*eth);
	}

	if (type)
		*type = ntohs(eth->ether_type);

	return (void*)((char *)eth + sizeof(*eth));
}

/* skip any 802.1q headers if necessary 
 * type is input/output
 */
void *trace_get_vlan_payload_from_ethernet_payload(void *ethernet, uint16_t *type,
		uint32_t *remaining)
{
	assert(type && "You must pass a type in!");

	if (*type == 0x8100) {
		libtrace_8021q_t *vlanhdr = (libtrace_8021q_t *)ethernet;

		if (remaining) {
			if (*remaining < sizeof(libtrace_8021q_t))
				return NULL;

			*remaining=*remaining-sizeof(libtrace_8021q_t);
		}

		*type = ntohs(vlanhdr->vlan_ether_type);

		return (void*)((char *)ethernet + sizeof(*vlanhdr));
	}

	return ethernet;
}

/* skip any MPLS headers if necessary, guessing what the next type is
 * type is input/output.  If the next type is "ethernet" this will
 * return a type of 0x0000.
 */
void *trace_get_mpls_payload_from_ethernet_payload(void *ethernet,
		uint16_t *type, uint32_t *remaining)
{
	assert(type && "You must pass a type in!");

	if (*type == 0x8847) {
		if ((((char*)ethernet)[2]&0x01)==0) {
			*type = 0x8847;
		}
		else {
			if (!remaining || *remaining>=5) {
				switch (((char*)ethernet)[4]&0xF0) {
					case 0x40:
						*type = 0x0800;
						break;
					case 0x60:
						*type = 0x86DD;
						break;
					default:
						/* Ethernet */
						*type = 0;
				}
			}
		}
		ethernet=(char*)ethernet+4;
		if (remaining) {
			if (*remaining<4)
				return NULL;
			else
				*remaining-=4;
		}


		return ethernet;
	}
	else
		return NULL;
}

static void *trace_get_payload_from_llcsnap(void *link,
		uint16_t *type, uint32_t *remaining)
{
	/* 64 byte capture. */
	libtrace_llcsnap_t *llc = (libtrace_llcsnap_t*)link;

	if (remaining) {
		if (*remaining < sizeof(libtrace_llcsnap_t))
			return NULL;
		*remaining-=(sizeof(libtrace_llcsnap_t));
	}

	llc = (libtrace_llcsnap_t*)((char *)llc);

	if (type) *type = ntohs(llc->type);

	return (void*)((char*)llc+sizeof(*llc));
}


static void *trace_get_payload_from_80211(void *link, uint16_t *type, uint32_t *remaining)
{
	libtrace_80211_t *wifi;
	uint16_t *eth; /* ethertype */
	int8_t extra = 0; /* how many QoS bytes to skip */
	
	if (remaining && *remaining < sizeof(libtrace_80211_t))
		return NULL;

	wifi=(libtrace_80211_t*)link;

	/* Data packet? */
	if (wifi->type != 2) {
		return NULL;
	}

	/* If FromDS and ToDS are both set then we have a four-address
	 * frame. Otherwise we have a three-address frame */
	if (!(wifi->to_ds && wifi->from_ds)) 
		extra -= 6; 
	
	/* Indicates QoS field present, see IEEE802.11e-2005 pg 21 */
	if (wifi->subtype & 0x8) 
		extra += 2;

	if (remaining && *remaining < sizeof(*eth))
		return NULL;

	eth=(uint16_t *)((char*)wifi+sizeof(*wifi)+extra);
	
	if (*eth == 0xaaaa)
		/* Payload contains an 802.2 LLC/SNAP frame */
		return trace_get_payload_from_llcsnap((void *)eth, type, remaining);
			
	/* Otherwise we assume an Ethernet II frame */
	if (type) *type=ntohs(*eth);
	if (remaining) *remaining = *remaining - sizeof(libtrace_80211_t) - extra - sizeof(*eth);
	
	return (void*)((char*)eth+sizeof(*eth));
}

static void *trace_get_payload_from_ppp(void *link, 
		uint16_t *type, uint32_t *remaining)
{
	/* 64 byte capture. */
	libtrace_ppp_t *ppp = (libtrace_ppp_t*)link;

	if (remaining) {
		if (*remaining < sizeof(libtrace_ppp_t))
			return NULL;
		*remaining-=sizeof(libtrace_ppp_t);
	}

	if (type) {
		switch(ntohs(ppp->protocol)) {
			case 0x0021: *type = 0x0800; break;
		}
	}


	return (void*)((char *)ppp+sizeof(*ppp));
}

typedef struct libtrace_chdlc_t {
	uint8_t address;	/** 0xF0 for unicast, 0xF8 for multicast */
	uint8_t control;
	uint16_t ethertype;
} libtrace_chdlc_t;

static void *trace_get_payload_from_chdlc(void *link, 
		uint16_t *type, uint32_t *remaining)
{
	libtrace_chdlc_t *chdlc = (libtrace_chdlc_t*)link;

	if (remaining) {
		if (*remaining < sizeof(libtrace_chdlc_t))
			return NULL;
		*remaining-=sizeof(libtrace_chdlc_t);
	}

	if (type) {
		*type=ntohs(chdlc->ethertype);
	}


	return (void*)((char *)chdlc+sizeof(*chdlc));
}

void *trace_get_payload_from_link(void *link, libtrace_linktype_t linktype, 
		uint16_t *ethertype, uint32_t *remaining)
{
	void *l = NULL;

	do {
		l = trace_get_payload_from_meta(link, &linktype, remaining);
		if (l != NULL) {
			link=l;
			continue;
		}
	} while (0);

	return trace_get_payload_from_layer2(link,linktype,ethertype,remaining);
	
}

DLLEXPORT void *trace_get_layer2(const libtrace_packet_t *packet,
		libtrace_linktype_t *linktype,
		uint32_t *remaining) 
{
	uint32_t dummyrem;
	
	assert(packet != NULL);
	assert(linktype != NULL);

	if (remaining == NULL)
		remaining = &dummyrem;
	
	void *meta = trace_get_packet_meta(packet, linktype, remaining);

	/* If there are no meta-data headers, we just return the start of the
	 * packet buffer, along with the linktype, etc.
	 */
	if (meta == NULL) 
		return trace_get_packet_buffer(packet, linktype, remaining);
	
	/* If there are meta-data headers, we need to skip over them until we
	 * find a non-meta data header and return that.
	 */
	for(;;) {
		void *nexthdr = trace_get_payload_from_meta(meta, 
				linktype, remaining);
		if (nexthdr == NULL)
			return meta;
		meta = nexthdr;
	}
}

DLLEXPORT
void *trace_get_payload_from_atm(void *link,
		uint8_t *type, uint32_t *remaining)
{
	libtrace_atm_capture_cell_t *cell;
	if (remaining && *remaining<sizeof(libtrace_atm_capture_cell_t))
		return NULL;
	cell=(libtrace_atm_capture_cell_t*)link;

	if (type)
		*type=cell->pt;

	if (remaining)
		*remaining-=sizeof(libtrace_atm_capture_cell_t);

	return ((char*)link)+sizeof(libtrace_atm_capture_cell_t);
}



DLLEXPORT void *trace_get_payload_from_layer2(void *link,
		libtrace_linktype_t linktype,
		uint16_t *ethertype,
		uint32_t *remaining)
{
	void *l;
	switch(linktype) {
		/* Packet Metadata headers, not layer2 headers */
		case TRACE_TYPE_80211_PRISM:
		case TRACE_TYPE_80211_RADIO:
		case TRACE_TYPE_PFLOG:
		case TRACE_TYPE_LINUX_SLL:
			return NULL;

		/* duck packets have no payload! */
		case TRACE_TYPE_DUCK:
			return NULL;

		/* The payload is in these packets does
		   not correspond to a genuine link-layer
		   */
		case TRACE_TYPE_METADATA:
			return NULL;

		case TRACE_TYPE_80211:
			return trace_get_payload_from_80211(link,ethertype,remaining);
		case TRACE_TYPE_ETH:
			return trace_get_payload_from_ethernet(link,ethertype,remaining);
		case TRACE_TYPE_NONE:
			if ((*(char*)link&0xF0) == 0x40)
				*ethertype=0x0800;
			else if ((*(char*)link&0xF0) == 0x60)
				*ethertype=0x86DD;
			return link; /* I love the simplicity */
		case TRACE_TYPE_PPP:
			return trace_get_payload_from_ppp(link,ethertype,remaining);
		case TRACE_TYPE_ATM:
			l=trace_get_payload_from_atm(link,NULL,remaining);
			/* FIXME: We shouldn't skip llcsnap here, we should return
			 * an ethertype for it (somehow)
			 */
			return (l ? trace_get_payload_from_llcsnap(l,
						ethertype, remaining):NULL);
		case TRACE_TYPE_LLCSNAP:
			return trace_get_payload_from_llcsnap(link,ethertype,remaining);

		case TRACE_TYPE_HDLC_POS:
			return trace_get_payload_from_chdlc(link,ethertype,
					remaining);
		/* TODO: Unsupported */
		case TRACE_TYPE_POS:
		case TRACE_TYPE_AAL5:
			return NULL;
	}
	return NULL;

}



