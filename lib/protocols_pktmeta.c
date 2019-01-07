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

#ifdef HAVE_WANDDER
#include <libwandder_etsili.h>
#endif

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

static void *trace_get_payload_from_etsili(const void *link,
                libtrace_linktype_t *type, uint32_t *remaining) {

#ifdef HAVE_WANDDER
        wandder_etsispec_t *dec;
        uint8_t *ccptr;

        /* XXX Bit annoying to be creating and freeing this every time */
        dec = wandder_create_etsili_decoder();
        wandder_attach_etsili_buffer(dec, (uint8_t *)link, *remaining, false);
        ccptr = wandder_etsili_get_cc_contents(dec, remaining, NULL, 0);
        /* Assuming all CCs are IP for now */
        *type = TRACE_TYPE_NONE;
        wandder_free_etsili_decoder(dec);
        return ccptr;

#else
	(void)link;
	(void)type;
        *remaining = 0;
        return NULL;
#endif

}

DLLEXPORT void *trace_get_packet_meta(const libtrace_packet_t *packet, 
		libtrace_linktype_t *linktype,
		uint32_t *remaining)
{
	uint32_t dummyrem;
	void *pktbuf = NULL;
	if (!packet) {
		fprintf(stderr, "NULL packet passed into trace_get_packet_meta()");
		return NULL;
	}
	if (!linktype) {
		fprintf(stderr, "NULL linkype passed into trace_get_packet_meta()");
		return NULL;
	}

	if (remaining == NULL)
		remaining = &dummyrem;

	pktbuf = trace_get_packet_buffer(packet, linktype, remaining);
	switch (*linktype) {
		case TRACE_TYPE_LINUX_SLL:
		case TRACE_TYPE_80211_RADIO:
		case TRACE_TYPE_80211_PRISM:
		case TRACE_TYPE_ERF_META:
                case TRACE_TYPE_ETSILI:
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
		case TRACE_TYPE_PCAPNG_META:
		case TRACE_TYPE_CONTENT_INVALID:
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
	uint16_t arphrd = 0;
	uint16_t next = 0;

	if (!meta) {
		fprintf(stderr, "NULL meta passed into trace_get_payload_from_meta()");
		return NULL;
	}
	if (!linktype) {
		fprintf(stderr, "NULL linktype passed into trace_get_payload_from_meta()");
		return NULL;
	}
	if (!remaining) {
		fprintf(stderr, "NULL remaining passed into trace_get_payload_from_meta()");
		return NULL;
	}

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
                case TRACE_TYPE_ETSILI:
                        nexthdr = trace_get_payload_from_etsili(meta,
                                        linktype, remaining);
                        return nexthdr;

		case TRACE_TYPE_PCAPNG_META:
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
		case TRACE_TYPE_ERF_META:
		case TRACE_TYPE_UNKNOWN:
		case TRACE_TYPE_CONTENT_INVALID:
			/* In this case, the pointer passed in does not point
			 * to a metadata header and so we cannot get the
			 * payload.
			 */
			return NULL;
	}
	/* Shouldn't get here */
	return NULL;
}

