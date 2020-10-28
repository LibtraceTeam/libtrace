/*
 *
 * Copyright (c) 2007-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */
#include "libtrace_int.h"
#include "libtrace.h"
#include "protocols.h"
#include <stdlib.h>
#include <string.h>

static void *trace_get_payload_from_ppp(void *link, uint16_t *type, uint32_t *remaining);

/* This file contains all the protocol decoding functions for layer 2 
 * (and 2.5) protocols. This includes functions for accessing MAC addresses.
 *
 * Supported protocols include (but are not limited to):
 * 	Ethernet
 * 	802.11
 * 	802.1q (vlan)
 * 	MPLS
 * 	PPPoE
 * 	LLCSnap
 * 	ATM
 */


/* Returns the payload from 802.3 ethernet.  Type optionally returned in
 * "type" in host byte order.  This will return a vlan header.
 */
void *trace_get_payload_from_ethernet(void *ethernet, 
		uint16_t *type,
		uint32_t *remaining)
{
	libtrace_ether_t *eth = (libtrace_ether_t*)ethernet;

	if (remaining) {
		if (*remaining < sizeof(*eth)) {
			*remaining = 0;
			return NULL;
		}
		*remaining-=sizeof(*eth);
	}

	if (type)
		*type = ntohs(eth->ether_type);

	return (void*)((char *)eth + sizeof(*eth));
}

/* Skip any 802.1q headers if necessary 
 * type is now output only (why check it if we don't need to?)
 */
void *trace_get_payload_from_vlan(void *ethernet, uint16_t *type,
		uint32_t *remaining)
{
	libtrace_8021q_t *vlanhdr = (libtrace_8021q_t *)ethernet;

	if (remaining) {
		if (*remaining < sizeof(libtrace_8021q_t)) {
			*remaining = 0;
			return NULL;
		}

		*remaining=*remaining-sizeof(libtrace_8021q_t);
	}

	if (type)
		*type = ntohs(vlanhdr->vlan_ether_type);

	return (void*)((char *)ethernet + sizeof(*vlanhdr));

}

int trace_destroy_layer2_headers(libtrace_layer2_headers_t *headers) {
	if (headers == NULL) {
		fprintf(stderr, "NULL libtrace_layer2_headers_t passed into "
			"trace_destroy_layer2_headers()\n");
		return -1;
	}

	if (headers->header != NULL) {
		free(headers->header);
	}
	free(headers);
	return 1;
}
libtrace_layer2_headers_t *trace_get_layer2_headers(libtrace_packet_t *packet) {

	char *ptr;
	libtrace_linktype_t linktype;
	uint32_t remaining;
	uint16_t ethertype;
	libtrace_layer2_headers_t *r;
	int allocated_headers = 0;

	if (packet == NULL) {
		fprintf(stderr, "NULL packet passed into trace_get_layer2_headers()\n");
		return NULL;
	}
	if (packet->trace == NULL) {
		fprintf(stderr, "Packet contains a NULL trace in trace_get_layer2_headers()\n");
		return NULL;
	}

	/* jump to layer 2 */
	ptr = trace_get_layer2(packet, &linktype, &remaining);
	/* packet does not contain layer2 */
	if (ptr == NULL) {
		return NULL;
	}

	/* allocate memory for the result */
        r = calloc(1, sizeof(libtrace_layer2_headers_t));
	if (r == NULL) {
		trace_set_err(packet->trace, TRACE_ERR_OUT_OF_MEMORY,
			"Unable to allocate memory in trace_get_layer2_headers()\n");
		return NULL;
	}
	/* Alloc enough space for 10 headers */
	r->header = calloc(1, sizeof(libtrace_layer2_header_t)*10);
	if (r->header == NULL) {
		trace_set_err(packet->trace, TRACE_ERR_OUT_OF_MEMORY,
			"Unable to allocate memory in trace_get_layer2_headers()\n");
		free(r);
		return NULL;
	}
	allocated_headers = 10;

	/* get the first layer2 header */
	ptr = trace_get_payload_from_layer2(ptr, linktype, &ethertype, &remaining);

	while (remaining != 0 && ptr != NULL) {

		if ((r->num+1) >= allocated_headers) {
			allocated_headers += 10;
			r->header = realloc(r->header,
				sizeof(libtrace_layer2_header_t)*allocated_headers);

			if (r->header == NULL) {
				trace_set_err(packet->trace, TRACE_ERR_OUT_OF_MEMORY,
					"Unable to allocate memory in trace_get_layer2_headers()");
				free(r);
				return NULL;
			}
		}

		/* Set the bitmask and get payload of the next layer2 header */
		switch (ethertype) {
			case (TRACE_ETHERTYPE_ARP):
				r->header[r->num].ethertype = ethertype;
                                r->header[r->num++].data = ptr;
                                r->bitmask |= TRACE_BITMASK_ARP;
                                /* arp cannot have any headers below it? */
				goto cleanup;
			case (TRACE_ETHERTYPE_8021Q):
				r->header[r->num].ethertype = ethertype;
                        	r->header[r->num++].data = ptr;
				r->bitmask |= TRACE_BITMASK_8021Q;
				ptr = (char *)trace_get_payload_from_vlan(ptr, &ethertype, &remaining);
				break;
			case (TRACE_ETHERTYPE_8021QS):
				r->header[r->num].ethertype = ethertype;
                        	r->header[r->num++].data = ptr;
				r->bitmask |= TRACE_BITMASK_8021QS;
				ptr = (char *)trace_get_payload_from_vlan(ptr, &ethertype, &remaining);
				break;
			case (TRACE_ETHERTYPE_MPLS):
				r->header[r->num].ethertype = ethertype;
                        	r->header[r->num++].data = ptr;
				r->bitmask |= TRACE_BITMASK_MPLS;
				ptr = (char *)trace_get_payload_from_mpls(ptr, &ethertype, &remaining);
				break;
			case (TRACE_ETHERTYPE_MPLS_MC):
				r->header[r->num].ethertype = ethertype;
                        	r->header[r->num++].data = ptr;
				r->bitmask |= TRACE_BITMASK_MPLS_MC;
				ptr = (char *)trace_get_payload_from_mpls(ptr, &ethertype, &remaining);
				break;
			case (TRACE_ETHERTYPE_PPP_DISC):
				r->header[r->num].ethertype = ethertype;
                        	r->header[r->num++].data = ptr;
				r->bitmask |= TRACE_BITMASK_PPP_DISC;
				ptr = (char *)trace_get_payload_from_ppp(ptr, &ethertype, &remaining);
				break;
			case (TRACE_ETHERTYPE_PPP_SES):
				r->header[r->num].ethertype = ethertype;
                        	r->header[r->num++].data = ptr;
				r->bitmask |= TRACE_BITMASK_PPP_SES;
				ptr = (char *)trace_get_payload_from_ppp(ptr, &ethertype, &remaining);
				break;
			case (TRACE_ETHERTYPE_LOOPBACK):
			case (TRACE_ETHERTYPE_IP):
			case (TRACE_ETHERTYPE_RARP):
			case (TRACE_ETHERTYPE_IPV6):
			default:
				goto cleanup;
		}
	}
cleanup:
	/* If no results were found free memory now and just return NULL */
	if (r->num == 0) {
		free(r->header);
		free(r);
		return NULL;
	}

	return r;
}

uint16_t trace_get_outermost_vlan(libtrace_packet_t *packet, uint8_t **vlanptr,
	uint32_t *remaining) {

	uint8_t *ptr;
	libtrace_linktype_t linktype;
	uint32_t rem;
	uint16_t vlanid = VLAN_NOT_FOUND;
	uint16_t ethertype = 0;

	if (!packet) {
		fprintf(stderr, "NULL packet passed into trace_get_outermost_vlan()\n");
		*vlanptr = NULL;
		*remaining = 0;
		return vlanid;
	}

	ptr = trace_get_layer2(packet, &linktype, &rem);
	/* No layer 2 */
	if (ptr == NULL) {
		*vlanptr = NULL;
		*remaining = 0;
		return vlanid;
	}

	while (ethertype != TRACE_ETHERTYPE_8021Q && ethertype != TRACE_ETHERTYPE_8021QS) {

		if (rem == 0 || ptr == NULL || ethertype == TRACE_ETHERTYPE_IP ||
			ethertype == TRACE_ETHERTYPE_IPV6) {

			*vlanptr = NULL;
			*remaining = 0;
                        return vlanid;
                }

		/* get the next layer 2 header */
	        ptr = trace_get_payload_from_layer2(ptr, linktype, &ethertype, &rem);
	}

	/* found a vlan header */
	uint32_t val = ntohl(*(uint32_t *)ptr);
	/* the id portion is only 12 bits */
	vlanid = (((val >> 16) << 4) >> 4);

	*remaining = rem;
	*vlanptr = ptr;
	return vlanid;
}

uint32_t trace_get_outermost_mpls(libtrace_packet_t *packet, uint8_t **mplsptr,
        uint32_t *remaining) {

	uint8_t *ptr;
	uint32_t mplslabel = MPLS_NOT_FOUND;
	libtrace_linktype_t linktype;
	uint32_t rem;
	uint16_t ethertype = 0;

	if (!packet) {
		fprintf(stderr, "NULL packet passed into trace_get_outermost_mpls()\n");
		*remaining = 0;
		*mplsptr = NULL;
		return mplslabel;
	}

	ptr = trace_get_layer2(packet, &linktype, &rem);
	/* No layer2 */
	if (ptr == NULL) {
		*remaining = 0;
		*mplsptr = NULL;
		return mplslabel;
	}

	/* loop over the packet until we find a mpls label */
	while (ethertype != TRACE_ETHERTYPE_MPLS) {
		if (rem == 0 || ptr == NULL) {

			*remaining = 0;
			*mplsptr = NULL;
			return mplslabel;
		}

		/* get next layer2 header */
		ptr = trace_get_payload_from_layer2(ptr, linktype, &ethertype, &rem);
	}

	uint32_t val = ntohl(*(uint32_t *)ptr);
	mplslabel = val >> 12;

	*remaining = rem;
	*mplsptr = ptr;
	return mplslabel;
}

libtrace_packet_t *trace_strip_packet(libtrace_packet_t *packet) {

        libtrace_ether_t *ethernet;
        libtrace_linktype_t linktype;
        uint16_t ethertype;
        uint32_t remaining;
        char *nextpayload;
        uint16_t finalethertype = 0;
        uint16_t caplen, removed = 0;
        char *dest;
        uint8_t done = 0;
        uint32_t oldrem;

        /* For now, this will just work for Ethernet packets. */
        ethernet = (libtrace_ether_t *)trace_get_layer2(packet, 
                        &linktype, &remaining);

        if (linktype != TRACE_TYPE_ETH) {
                return packet;
        }

        /* No headers to strip, return the original packet */
        if (ethernet->ether_type == TRACE_ETHERTYPE_IP ||
                        ethernet->ether_type == TRACE_ETHERTYPE_IPV6) {
                return packet;
        }

        if (remaining <= sizeof(libtrace_ether_t))
                return packet;

        caplen = trace_get_capture_length(packet);
        ethertype = ntohs(ethernet->ether_type);
        dest = ((char *)ethernet) + sizeof(libtrace_ether_t);
        nextpayload = dest;
        remaining -= sizeof(libtrace_ether_t);

        /* I'd normally use trace_get_layer3 here, but it works out faster
         * to do it this way (mostly less function call overhead).
         *
         * XXX This approach is going to just strip everything between the
         * Ethernet and IP headers -- is there a use case where someone
         * might want to selectively strip headers?
         */
        while (!done) {

                if (nextpayload == NULL || remaining == 0)
                        break;

                oldrem = remaining;
                switch (ethertype) {

                case TRACE_ETHERTYPE_8021Q:
                        nextpayload = (char *)trace_get_payload_from_vlan(
                                        nextpayload,
                                        &ethertype, &remaining);
                        removed += (oldrem - remaining);
                        break;

                case TRACE_ETHERTYPE_MPLS:
                        nextpayload = (char *)trace_get_payload_from_mpls(
                                        nextpayload,
                                        &ethertype, &remaining);
                        removed += (oldrem - remaining);
                        break;
                case TRACE_ETHERTYPE_PPP_SES:
                        nextpayload = (char *)trace_get_payload_from_pppoe(
                                        nextpayload,
                                        &ethertype, &remaining);
                        removed += (oldrem - remaining);
                        break;

                case TRACE_ETHERTYPE_IP:
                case TRACE_ETHERTYPE_IPV6:
                default:
                        if (finalethertype == 0)
                                finalethertype = ethertype;
                        done = true;
                        break;
                }
        }

        if (nextpayload != NULL && removed > 0) {

                ethernet->ether_type = ntohs(finalethertype);
                trace_set_capture_length(packet, caplen - removed);
                memmove(nextpayload - (dest - (char *)packet->payload), 
                        packet->payload, 
                        (dest - (char *)packet->payload));
                packet->payload = nextpayload - (dest - (char *)packet->payload);
                packet->cached.l2_header = NULL;
        }
        
        return packet;

}

/* Skip any MPLS headers if necessary, guessing what the next type is
 * type is input/output.  If the next type is "ethernet" this will
 * return a type of 0x0000.
 */
void *trace_get_payload_from_mpls(void *ethernet, uint16_t *type, 
		uint32_t *remaining) {
	/* Ensure supplied type is not NULL */
	if (!type) {
		fprintf(stderr, "NULL type passed into trace_get_payload_from_mpls()\n");
		return NULL;
	}

	if ((((char*)ethernet)[2]&0x01)==0) {
		/* The MPLS Stack bit is set */
		*type = TRACE_ETHERTYPE_MPLS;
	}
	else {
		if (!remaining || *remaining>=5) {
			switch (((char*)ethernet)[4]&0xF0) {
				case 0x40:	/* IPv4 */
					*type = TRACE_ETHERTYPE_IP;
					break;
				case 0x60:	/* IPv6 */
					*type = TRACE_ETHERTYPE_IPV6;
					break;
				default:	/* VPLS */
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

static void *trace_get_payload_from_llcsnap(void *link,
		uint16_t *type, uint32_t *remaining)
{
	/* 64 byte capture. */
	libtrace_llcsnap_t *llc = (libtrace_llcsnap_t*)link;

	if (remaining) {
		if (*remaining < sizeof(libtrace_llcsnap_t)) {
			*remaining = 0;
			return NULL;
		}
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
	
	if (remaining && *remaining < sizeof(libtrace_80211_t)) {
		*remaining = 0;
		return NULL;
	}

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

	if (remaining && *remaining < sizeof(*eth)) {
		*remaining = 0;
		return NULL;
	}

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
		if (*remaining < sizeof(libtrace_ppp_t)) {
			*remaining = 0;
			return NULL;
		}
		*remaining-=sizeof(libtrace_ppp_t);
	}

	if (type) {
		switch(ntohs(ppp->protocol)) {
			case 0x0021: *type = TRACE_ETHERTYPE_IP; break;
			case 0x0057: *type = TRACE_ETHERTYPE_IPV6; break;				
			/* If it isn't IP, then it is probably PPP control and
			 * I can't imagine anyone caring about that too much
			 */
			default: *type = 0; break;
		}
	}


	return (void*)((char *)ppp+sizeof(*ppp));
}

void *trace_get_payload_from_pppoe(void *link, uint16_t *type, 
		uint32_t *remaining) {
	/* Ensure type supplied is not NULL */
	if (!type) {
		fprintf(stderr, "NULL type passed into trace_get_payload_from_pppoe()\n");
		return NULL;
	}

	if (remaining) {
		if (*remaining < sizeof(libtrace_pppoe_t)) {
			*remaining = 0;
			return NULL;
		}
		*remaining -= sizeof(libtrace_pppoe_t);
	}
	
	/* PPPoE is always followed by PPP */
	return trace_get_payload_from_ppp(link + sizeof(libtrace_pppoe_t),
			type, remaining);
}
	
/* Header for CHDLC framing */
typedef struct libtrace_chdlc_t {
	uint8_t address;	/** 0xF0 for unicast, 0xF8 for multicast */
	uint8_t control;	/** Always 0x00 */
	uint16_t ethertype;
} libtrace_chdlc_t;

/* Header for PPP in HDLC-like framing */
typedef struct libtrace_ppp_hdlc_t {
	uint8_t address;	/** Always should be 0xff */
	uint8_t control;	/** Always should be 0x03 */
	uint16_t protocol;	
} libtrace_ppp_hdlc_t;

static void *trace_get_payload_from_chdlc(void *link, uint16_t *type,
		uint32_t *remaining) {

	libtrace_chdlc_t *chdlc = (libtrace_chdlc_t *)link;

	if (remaining) {
		if (*remaining < sizeof(libtrace_chdlc_t)) {
			*remaining = 0;
			return NULL;
		}
		*remaining -= sizeof(libtrace_chdlc_t);
	}

	if (type) {
		*type = ntohs(chdlc->ethertype);
	}

	return (void *)((char *)chdlc + sizeof(*chdlc));

}

static void *trace_get_payload_from_ppp_hdlc(void *link, 
		uint16_t *type, uint32_t *remaining)
{
	libtrace_ppp_hdlc_t *ppp_hdlc = (libtrace_ppp_hdlc_t*)link;

	if (remaining) {
		if (*remaining < sizeof(libtrace_ppp_hdlc_t)) {
			*remaining = 0;
			return NULL;
		}
		*remaining-=sizeof(libtrace_ppp_hdlc_t);
	}

	if (type) {
		/* http://www.iana.org/assignments/ppp-numbers */

		switch(ntohs(ppp_hdlc->protocol)) {
			case 0x0021: /* IP */
				*type = TRACE_ETHERTYPE_IP;
				break;
			case 0x0057: /* IPV6 */
				*type = TRACE_ETHERTYPE_IPV6;
				break;
			case 0xc021: /* Link Control Protocol */
				*type = 0; /* No ethertype for this */
				break;

			default:
				printf("Unknown chdlc type: %04x\n",
						ntohs(ppp_hdlc->protocol));
				*type = 0; /* Unknown */
		}
	}


	return (void*)((char *)ppp_hdlc+sizeof(*ppp_hdlc));
}

void *trace_get_payload_from_link(void *link, libtrace_linktype_t linktype, 
		uint16_t *ethertype, uint32_t *remaining)
{
	void *l = NULL;

	do {
		l = trace_get_payload_from_meta(link, &linktype, remaining);
		if (l != NULL) {
			link=l;
		}
	} while (l != NULL);

	return trace_get_payload_from_layer2(link,linktype,ethertype,remaining);
	
}

DLLEXPORT void *trace_get_layer2(const libtrace_packet_t *packet,
		libtrace_linktype_t *linktype,
		uint32_t *remaining) 
{
	uint32_t dummyrem;
	void *meta = NULL;
        int done = 0;
        uint32_t wire_len;

	if (!packet) {
		fprintf(stderr, "NULL packet passed into trace_get_layer2()\n");
		return NULL;
	}
	if (!linktype) {
		fprintf(stderr, "NULL linktype passed into trace_get_layer2()\n");
		return NULL;
	}

	if (remaining == NULL)
		remaining = &dummyrem;

	if (packet->cached.l2_header) {
		/* Use cached values */
		*linktype = packet->cached.link_type;
		*remaining = packet->cached.l2_remaining;
		return packet->cached.l2_header;
	}

	/* Code looks a bit inefficient, but I'm actually trying to avoid
	 * calling trace_get_packet_buffer more than once like we used to.
	 */
	meta = trace_get_packet_buffer(packet, linktype, remaining);
        if (meta == NULL) {
                return NULL;
        }

	/* If there are no meta-data headers, we just return the start of the
	 * packet buffer, along with the linktype, etc.
	 */
	switch(*linktype) {
		/* meta points to a layer 2 header! */
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
		case TRACE_TYPE_NONDATA:
		case TRACE_TYPE_OPENBSD_LOOP:
			((libtrace_packet_t*)packet)->cached.l2_header = meta;
			((libtrace_packet_t*)packet)->cached.l2_remaining = *remaining;
			return meta;
		case TRACE_TYPE_LINUX_SLL:
		case TRACE_TYPE_80211_RADIO:
		case TRACE_TYPE_80211_PRISM:
		case TRACE_TYPE_PFLOG:
		case TRACE_TYPE_ERF_META:
		case TRACE_TYPE_PCAPNG_META:
		case TRACE_TYPE_TZSP:
                case TRACE_TYPE_ETSILI:
                case TRACE_TYPE_CORSAROTAG:
                case TRACE_TYPE_XDP:
			break;
		case TRACE_TYPE_UNKNOWN:
		case TRACE_TYPE_CONTENT_INVALID:
			return NULL;
	}

	/* If there are meta-data headers, we need to skip over them until we
	 * find a non-meta data header and return that.
	 */
	while (!done) {
		void *nexthdr = trace_get_payload_from_meta(meta, 
				linktype, remaining);
		
		if (nexthdr != NULL) {
                        meta = nexthdr;
                        continue;
                }

                switch (*linktype) {
                        /* meta points to a layer 2 header! */
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
                        case TRACE_TYPE_NONDATA:
                        case TRACE_TYPE_OPENBSD_LOOP:
                                done = 1;
                                break;
                        case TRACE_TYPE_LINUX_SLL:
                        case TRACE_TYPE_80211_RADIO:
                        case TRACE_TYPE_80211_PRISM:
                        case TRACE_TYPE_PFLOG:
                        case TRACE_TYPE_ERF_META:
                        case TRACE_TYPE_PCAPNG_META:
                        case TRACE_TYPE_TZSP:
                        case TRACE_TYPE_ETSILI:
                        case TRACE_TYPE_CORSAROTAG:
                        case TRACE_TYPE_XDP:
                                meta = nexthdr;  // should never hit this?
                                break;
                        case TRACE_TYPE_UNKNOWN:
                        case TRACE_TYPE_CONTENT_INVALID:
                                return NULL;
                }

                if (meta == NULL) {
                        return NULL;
                }
	}

        /* L2 remaining should never exceed wire length, to avoid treating
         * capture padding as genuine packet content.
         *
         * For example, in Auck 4 there is a trace where the IP header
         * length is incorrect (24 bytes) followed by a 20 byte TCP
         * header. Total IP length is 40 bytes. As a result, the
         * legacyatm padding gets treated as the "missing" bytes of
         * the TCP header, which isn't the greatest. We're probably
         * better off returning an incomplete TCP header in that case.
         */

        wire_len = (uint32_t) trace_get_wire_length(packet);
        if (wire_len > 0 && wire_len < *remaining) {
                *remaining = wire_len;
        }

        ((libtrace_packet_t*)packet)->cached.l2_header = meta;
        ((libtrace_packet_t*)packet)->cached.l2_remaining = *remaining;

        return meta;
}

DLLEXPORT
void *trace_get_payload_from_atm(void *link,
		uint8_t *type, uint32_t *remaining)
{
	libtrace_atm_capture_cell_t *cell;
	if (remaining && *remaining<sizeof(libtrace_atm_capture_cell_t)) {
		*remaining = 0;
		return NULL;
	}
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

	if (linktype == TRACE_TYPE_UNKNOWN ||
                        linktype == TRACE_TYPE_CONTENT_INVALID) {
		fprintf(stderr, "Unable to determine linktype for packet\n");
		return NULL;
	}

        if (link == NULL) {
                return NULL;
        }

	switch(linktype) {
		/* Packet Metadata headers, not layer2 headers */
		case TRACE_TYPE_80211_PRISM:
		case TRACE_TYPE_80211_RADIO:
		case TRACE_TYPE_PFLOG:
		case TRACE_TYPE_LINUX_SLL:
                case TRACE_TYPE_ETSILI:
			return NULL;

		/* duck packets have no payload! */
		case TRACE_TYPE_DUCK:
			return NULL;

		/* The payload is in these packets does
		   not correspond to a genuine link-layer
		   */
		case TRACE_TYPE_METADATA:
		case TRACE_TYPE_NONDATA:
		case TRACE_TYPE_PCAPNG_META:
		case TRACE_TYPE_TZSP:
		case TRACE_TYPE_ERF_META:
                case TRACE_TYPE_CORSAROTAG:
		case TRACE_TYPE_CONTENT_INVALID:
		case TRACE_TYPE_UNKNOWN:
                case TRACE_TYPE_XDP:
			return NULL;

		case TRACE_TYPE_80211:
			return trace_get_payload_from_80211(link,ethertype,remaining);
		case TRACE_TYPE_ETH:
			return trace_get_payload_from_ethernet(link,ethertype,remaining);
		case TRACE_TYPE_NONE:
                        if (*remaining == 0) {
                                return NULL;
                        }

			if ((*(char*)link&0xF0) == 0x40)
				*ethertype=TRACE_ETHERTYPE_IP;	 /* IPv4 */
			else if ((*(char*)link&0xF0) == 0x60)
				*ethertype=TRACE_ETHERTYPE_IPV6; /* IPv6 */
                        else
                                return NULL;            /* No idea */
			return link; /* I love the simplicity */
		case TRACE_TYPE_PPP:
			return trace_get_payload_from_ppp(link,ethertype,remaining);
		case TRACE_TYPE_ATM:
			l=trace_get_payload_from_atm(link,NULL,remaining);
			/* FIXME: We shouldn't skip llcsnap here, we should 
			 * return an ethertype for it (somehow)
			 */
			return (l ? trace_get_payload_from_llcsnap(l,
						ethertype, remaining):NULL);
		case TRACE_TYPE_LLCSNAP:
			return trace_get_payload_from_llcsnap(link,ethertype,remaining);

		case TRACE_TYPE_HDLC_POS:
			return trace_get_payload_from_chdlc(link,ethertype,
					remaining);
		case TRACE_TYPE_POS:
			return trace_get_payload_from_ppp_hdlc(link,ethertype,
					remaining);
		/* TODO: Unsupported */
		case TRACE_TYPE_AAL5:
			return NULL;

		case TRACE_TYPE_OPENBSD_LOOP:
                        if (*remaining <= 4) {
                                return NULL;
                        }
			link = link + 4; /* Loopback header is 4 bytes */
			if ((*(char*)link&0xF0) == 0x40)
				*ethertype=TRACE_ETHERTYPE_IP;	 /* IPv4 */
			else if ((*(char*)link&0xF0) == 0x60)
				*ethertype=TRACE_ETHERTYPE_IPV6; /* IPv6 */
                        else
                                return NULL;
			return link; /* I love the simplicity */
		

	}
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
        struct libtrace_80211_t *w;
        if (wifi == NULL) return NULL;
        w = (struct libtrace_80211_t *) wifi;

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
	/* Ensure the supplied packet is not NULL */
	if (!packet) {
		fprintf(stderr, "NULL packet passed into trace_get_source_mac()\n");
		return NULL;
	}

        void *link;
        uint32_t remaining;
        libtrace_linktype_t linktype;
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
		case TRACE_TYPE_NONDATA:
		case TRACE_TYPE_OPENBSD_LOOP:
		case TRACE_TYPE_ERF_META:
		case TRACE_TYPE_PCAPNG_META:
		case TRACE_TYPE_TZSP:
		case TRACE_TYPE_UNKNOWN:
		case TRACE_TYPE_CONTENT_INVALID:
                case TRACE_TYPE_XDP:
                        return NULL;

                /* Metadata headers should already be skipped */
                case TRACE_TYPE_LINUX_SLL:
                case TRACE_TYPE_80211_PRISM:
                case TRACE_TYPE_80211_RADIO:
                case TRACE_TYPE_ETSILI:
                case TRACE_TYPE_CORSAROTAG:
			fprintf(stderr, "Metadata headers should already be skipped in trace_get_source_mac()\n");
			return NULL;
        }
        fprintf(stderr,"%s not implemented for linktype %i\n", __func__, linktype);
        return NULL;
}

DLLEXPORT uint8_t *trace_get_destination_mac(libtrace_packet_t *packet) {
	/* Ensure the supplied packet is not NULL */
	if (!packet) {
		fprintf(stderr, "NULL packet passed into trace_get_destination_mac()\n");
		return NULL;
	}

        void *link;
        libtrace_linktype_t linktype;
        uint32_t remaining;
        libtrace_80211_t *wifi;
        libtrace_ether_t *ethptr;

        link = trace_get_layer2(packet,&linktype,&remaining);

        ethptr = (libtrace_ether_t*)link;


        if (!link)
                return NULL;

        switch (linktype) {
                case TRACE_TYPE_80211:
                        wifi=(libtrace_80211_t*)link;
                        return (uint8_t*)&wifi->mac1;
                case TRACE_TYPE_ETH:
                        return (uint8_t*)&ethptr->ether_dhost;
                case TRACE_TYPE_POS:
                case TRACE_TYPE_NONE:
                case TRACE_TYPE_ATM:
                case TRACE_TYPE_HDLC_POS:
                case TRACE_TYPE_PFLOG:
                case TRACE_TYPE_DUCK:
                case TRACE_TYPE_METADATA:
		case TRACE_TYPE_AAL5:
		case TRACE_TYPE_LLCSNAP:
		case TRACE_TYPE_PPP:	
		case TRACE_TYPE_NONDATA:
		case TRACE_TYPE_OPENBSD_LOOP:
		case TRACE_TYPE_ERF_META:
		case TRACE_TYPE_PCAPNG_META:
		case TRACE_TYPE_TZSP:
		case TRACE_TYPE_UNKNOWN:
		case TRACE_TYPE_CONTENT_INVALID:
                case TRACE_TYPE_XDP:
                        /* No MAC address */
                        return NULL;
                /* Metadata headers should already be skipped */
                case TRACE_TYPE_LINUX_SLL:
                case TRACE_TYPE_80211_PRISM:
                case TRACE_TYPE_80211_RADIO:
                case TRACE_TYPE_CORSAROTAG:
                case TRACE_TYPE_ETSILI:
			fprintf(stderr, "Metadata headers should already be skipped in trace_get_destination_mac()\n");
			return NULL;
        }
        fprintf(stderr,"Not implemented\n");
        return NULL;
}

