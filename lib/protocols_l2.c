/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Daniel Lawson 
 *          Perry Lorier
 *          Shane Alcock 
 *          
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libtrace; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 *
 */

#include "libtrace_int.h"
#include "libtrace.h"
#include "protocols.h"
#include <assert.h>
#include <stdlib.h>


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

/* Skip any MPLS headers if necessary, guessing what the next type is
 * type is input/output.  If the next type is "ethernet" this will
 * return a type of 0x0000.
 */
void *trace_get_payload_from_mpls(void *ethernet, uint16_t *type, 
		uint32_t *remaining)
{
	
	assert(type);
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
	assert(type);
	
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
	
	assert(packet != NULL);
	assert(linktype != NULL);

	if (remaining == NULL)
		remaining = &dummyrem;

	if (packet->l2_header) {
		/* Use cached values */
		*linktype = packet->link_type;
		*remaining = packet->l2_remaining;
		return packet->l2_header;
	}

	/* Code looks a bit inefficient, but I'm actually trying to avoid
	 * calling trace_get_packet_buffer more than once like we used to.
	 */
	
	meta = trace_get_packet_buffer(packet, linktype, remaining);

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
			((libtrace_packet_t*)packet)->l2_header = meta;
			((libtrace_packet_t*)packet)->l2_remaining = *remaining;
			return meta;
		case TRACE_TYPE_LINUX_SLL:
		case TRACE_TYPE_80211_RADIO:
		case TRACE_TYPE_80211_PRISM:
		case TRACE_TYPE_PFLOG:
			break;
		case TRACE_TYPE_UNKNOWN:
			return NULL;
	}

	/* If there are meta-data headers, we need to skip over them until we
	 * find a non-meta data header and return that.
	 */
	for(;;) {
		void *nexthdr = trace_get_payload_from_meta(meta, 
				linktype, remaining);
		
		if (nexthdr == NULL) {
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
					((libtrace_packet_t*)packet)->l2_header = meta;
					((libtrace_packet_t*)packet)->l2_remaining = *remaining;
					return meta;
				case TRACE_TYPE_LINUX_SLL:
				case TRACE_TYPE_80211_RADIO:
				case TRACE_TYPE_80211_PRISM:
				case TRACE_TYPE_PFLOG:
					break;
				case TRACE_TYPE_UNKNOWN:
					return NULL;
			}
			
			/* Otherwise, we must have hit the end of the packet */
			return NULL;
		}
	 
	 	
		meta = nexthdr;
	}

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

	if (linktype == TRACE_TYPE_UNKNOWN) {
		fprintf(stderr, "Unable to determine linktype for packet\n");
		return NULL;
	}
	
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
		case TRACE_TYPE_NONDATA:
		case TRACE_TYPE_UNKNOWN:
			return NULL;

		case TRACE_TYPE_80211:
			return trace_get_payload_from_80211(link,ethertype,remaining);
		case TRACE_TYPE_ETH:
			return trace_get_payload_from_ethernet(link,ethertype,remaining);
		case TRACE_TYPE_NONE:
			if ((*(char*)link&0xF0) == 0x40)
				*ethertype=TRACE_ETHERTYPE_IP;	 /* IPv4 */
			else if ((*(char*)link&0xF0) == 0x60)
				*ethertype=TRACE_ETHERTYPE_IPV6; /* IPv6 */
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
			link = link + 4; /* Loopback header is 4 bytes */
			if ((*(char*)link&0xF0) == 0x40)
				*ethertype=TRACE_ETHERTYPE_IP;	 /* IPv4 */
			else if ((*(char*)link&0xF0) == 0x60)
				*ethertype=TRACE_ETHERTYPE_IPV6; /* IPv6 */
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
		case TRACE_TYPE_NONDATA:
		case TRACE_TYPE_OPENBSD_LOOP:
		case TRACE_TYPE_UNKNOWN:
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
		case TRACE_TYPE_UNKNOWN:
                        /* No MAC address */
                        return NULL;
                /* Metadata headers should already be skipped */
                case TRACE_TYPE_LINUX_SLL:
                case TRACE_TYPE_80211_PRISM:
                case TRACE_TYPE_80211_RADIO:
                        assert(!"Metadata headers should already be skipped");
                        break;
        }
        fprintf(stderr,"Not implemented\n");
        assert(0);
        return NULL;
}

