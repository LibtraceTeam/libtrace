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

/* This file contains all the protocol decoding functions for the meta-data
 * headers that may be prepended to captured packets.
 *
 * Supported protocols include (but are not limited to):
 * 	Linux SLL
 * 	PFLOG
 * 	RadioTap
 * 	Prism
 */

/* NB: type is returned as an ARPHRD_ type for SLL*/
void *trace_get_payload_from_linux_sll(const void *link,
		uint16_t *arphrd_type, uint16_t *next, 
		uint32_t *remaining) 
{
	libtrace_sll_header_t *sll;

	sll = (libtrace_sll_header_t*) link;

	if (remaining) {
		if (*remaining < sizeof(*sll)) {
			*remaining = 0;
			return NULL;
		}
		*remaining-=sizeof(*sll);
	}

	/* The SLL header is actually in place of a link layer header, so
	 * we want to use the protocol field to tell our caller what the
	 * next header is going to be */
	if (next) *next = (libtrace_linktype_t)(ntohs(sll->protocol));
	if (arphrd_type) *arphrd_type = ntohs(sll->hatype);

	return (void*)((char*)sll+sizeof(*sll));

}

/* NB: type is returned as an ethertype */
static void *trace_get_payload_from_pflog(const void *link,
		libtrace_linktype_t *type, uint32_t *remaining)
{
	libtrace_pflog_header_t *pflog = (libtrace_pflog_header_t*)link;
	if (remaining) {
		if (*remaining<sizeof(*pflog)) {
			*remaining = 0;
			return NULL;
		}
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
		/* Prism header is 144 bytes long */
		if (*remaining<144) {
			*remaining = 0;
			return NULL;
		}
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
		if (*remaining < rtaplen) {
			*remaining = 0;
			return NULL;
		}
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
	void *pktbuf = NULL;
	assert(packet != NULL);
	assert(linktype != NULL);
	
	if (remaining == NULL) 
		remaining = &dummyrem;
	
	pktbuf = trace_get_packet_buffer(packet, linktype, remaining);
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
		case TRACE_TYPE_NONDATA:
		case TRACE_TYPE_OPENBSD_LOOP:
		case TRACE_TYPE_UNKNOWN:
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
	uint16_t next;
	
	assert(meta != NULL);
	assert(linktype != NULL);
	assert(remaining != NULL);
	
	switch(*linktype) {
		case TRACE_TYPE_LINUX_SLL:
			nexthdr = trace_get_payload_from_linux_sll(meta,
					&arphrd, &next, remaining);

			/* Ethernet header is usually absent in SLL captures,
			 * so we don't want to skip it just yet */
			if (arphrd_type_to_libtrace(arphrd) == TRACE_TYPE_ETH && next != 0x0060) 
				*linktype = TRACE_TYPE_NONE; 
			else 
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
		case TRACE_TYPE_NONDATA:
		case TRACE_TYPE_OPENBSD_LOOP:
		case TRACE_TYPE_UNKNOWN:
			/* In this case, the pointer passed in does not point
			 * to a metadata header and so we cannot get the
			 * payload.
			 */
			return NULL;
	}
	/* Shouldn't get here */
	return NULL;
}

