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

#include "config.h"
#include "libtrace.h"

#include "rt_protocol.h"
#include <assert.h>
#include "libtrace_int.h"
#include <stdlib.h>
#include <string.h>

#include "libtrace_arphrd.h" 


/* This file maps libtrace types to/from pcap DLT and erf types
 *
 * When adding a new linktype to libtrace, add the mapping(s) here,
 * and add the understanding of the type to get_ip(), and perhaps
 * get_{source,destination}_mac (if your linklayer has mac's)
 */

libtrace_linktype_t pcap_linktype_to_libtrace(libtrace_dlt_t linktype)
{
	switch(linktype) {
		case TRACE_DLT_RAW:
		case TRACE_DLT_LINKTYPE_RAW: return TRACE_TYPE_NONE;
		case TRACE_DLT_EN10MB: return TRACE_TYPE_ETH;
		case TRACE_DLT_IEEE802_11: return TRACE_TYPE_80211;
		case TRACE_DLT_LINUX_SLL: return TRACE_TYPE_LINUX_SLL;
		case TRACE_DLT_PFLOG: return TRACE_TYPE_PFLOG;
        	case TRACE_DLT_IEEE802_11_RADIO: return TRACE_TYPE_80211_RADIO;
		case TRACE_DLT_ATM_RFC1483: return TRACE_TYPE_LLCSNAP;
		case TRACE_DLT_PPP: return TRACE_TYPE_PPP;
		case TRACE_DLT_PPP_SERIAL: return TRACE_TYPE_POS;
		case TRACE_DLT_C_HDLC: return TRACE_TYPE_HDLC_POS;
		case TRACE_DLT_OPENBSD_LOOP: return TRACE_TYPE_OPENBSD_LOOP;
		/* Unhandled */
		case TRACE_DLT_ERROR:
		case TRACE_DLT_NULL: 	/* Raw IP frame with a BSD specific
					 * header If you want raw L3 headers
					 * use TRACE_DLT_RAW
					 */
			break;
	}
	return TRACE_TYPE_UNKNOWN;
}

libtrace_dlt_t libtrace_to_pcap_dlt(libtrace_linktype_t type)
{
	/* If pcap doesn't have a DLT, you can either ask pcap to register
	 * you a DLT, (and perhaps write a tcpdump decoder for it), or you
	 * can add it to demote_packet
	 */
	switch(type) {
		case TRACE_TYPE_NONE: return TRACE_DLT_RAW; 
		case TRACE_TYPE_ETH: return TRACE_DLT_EN10MB;
		case TRACE_TYPE_80211: return TRACE_DLT_IEEE802_11;
		case TRACE_TYPE_LINUX_SLL: return TRACE_DLT_LINUX_SLL;
		case TRACE_TYPE_PFLOG: return TRACE_DLT_PFLOG;
		case TRACE_TYPE_80211_RADIO: return TRACE_DLT_IEEE802_11_RADIO;
		case TRACE_TYPE_LLCSNAP: return TRACE_DLT_ATM_RFC1483;
		case TRACE_TYPE_PPP:	return TRACE_DLT_PPP;
		case TRACE_TYPE_HDLC_POS: return TRACE_DLT_C_HDLC;
		/* Theres more than one type of PPP.  Who knew? */
		case TRACE_TYPE_POS:	return TRACE_DLT_PPP_SERIAL; 
		case TRACE_TYPE_OPENBSD_LOOP: return TRACE_DLT_OPENBSD_LOOP;

		/* Below here are unsupported conversions */
		/* Despite hints to the contrary, there is no DLT
		 * for 'raw atm packets that happen to be missing
		 * the HEC' or even 'raw atm packets that have a hec'.
		 *
		 * The closest are DLT_ATM_RFC1483 but that doesn't
		 * include the ATM header, only the LLCSNAP header.
		 */
		case TRACE_TYPE_ATM: 
		/* pcap has no DLT for DUCK */
		case TRACE_TYPE_DUCK:
		/* Used for test traces within WAND */
		case TRACE_TYPE_80211_PRISM: 	
		/* Probably == PPP */
		/* TODO: We haven't researched these yet */
		case TRACE_TYPE_AAL5:
		case TRACE_TYPE_METADATA:
		case TRACE_TYPE_NONDATA:
			break;
		case TRACE_TYPE_UNKNOWN:
			break;
	}
	return TRACE_DLT_ERROR;
}

static libtrace_dlt_t pcap_dlt_to_pcap_linktype(libtrace_dlt_t linktype)
{
	switch (linktype) {
		case TRACE_DLT_RAW: return TRACE_DLT_LINKTYPE_RAW;
		default:
				    return linktype;
	}
}

libtrace_dlt_t libtrace_to_pcap_linktype(libtrace_linktype_t type)
{
	return pcap_dlt_to_pcap_linktype(libtrace_to_pcap_dlt(type));
}

libtrace_rt_types_t pcap_linktype_to_rt(libtrace_dlt_t linktype) 
{
	/* For pcap the rt type is just the linktype + a fixed value */
	return pcap_dlt_to_pcap_linktype(linktype) + TRACE_RT_DATA_DLT;
}

libtrace_rt_types_t bpf_linktype_to_rt(libtrace_dlt_t linktype) {
	return pcap_dlt_to_pcap_linktype(linktype) + TRACE_RT_DATA_BPF;

}

libtrace_dlt_t rt_to_pcap_linktype(libtrace_rt_types_t rt_type)
{
	
	if (rt_type >= TRACE_RT_DATA_DLT && rt_type < TRACE_RT_DATA_DLT_END) {
		/* RT type is in the pcap range */
		return rt_type - TRACE_RT_DATA_DLT;
	} 
	else if (rt_type >= TRACE_RT_DATA_BPF && rt_type < TRACE_RT_DATA_BPF_END) {
		return rt_type - TRACE_RT_DATA_BPF;
	}
	
	fprintf(stderr, "Error: RT type %u cannot be converted to a pcap DLT\n", rt_type);
	assert(rt_type >= TRACE_RT_DATA_DLT && rt_type < TRACE_RT_DATA_BPF_END);
	return 0;	/* satisfy warnings */
}

libtrace_linktype_t erf_type_to_libtrace(uint8_t erf)
{
	switch (erf) {
		case TYPE_HDLC_POS:	return TRACE_TYPE_HDLC_POS;
		case TYPE_ETH:		return TRACE_TYPE_ETH;
		case TYPE_ATM:		return TRACE_TYPE_ATM;
		case TYPE_AAL5:		return TRACE_TYPE_AAL5;
		case TYPE_DSM_COLOR_ETH:return TRACE_TYPE_ETH;
		case TYPE_IPV4:		return TRACE_TYPE_NONE;
		case TYPE_IPV6:		return TRACE_TYPE_NONE;
	}
	return ~0U;
}

uint8_t libtrace_to_erf_type(libtrace_linktype_t linktype)
{
	switch(linktype) {
		case TRACE_TYPE_HDLC_POS: return TYPE_HDLC_POS;
		case TRACE_TYPE_ETH:	return TYPE_ETH;
		case TRACE_TYPE_ATM:	return TYPE_ATM;
		case TRACE_TYPE_AAL5:	return TYPE_AAL5;
		
		/* Not technically correct! Could be IPv6 packet 
		 *
		 * TODO: Maybe we want TRACE_TYPE_RAW_IPV4 and
		 * TRACE_TYPE_RAW_IPV6 to replace TRACE_TYPE_NONE.
		 * Still need a good way to figure out how to convert
		 * TRACE_DLT_LINKTYPE_RAW into the correct type for the
		 * IP version though :( */
		case TRACE_TYPE_NONE:	return TYPE_IPV4;
		/* Unsupported conversions */
		case TRACE_TYPE_LLCSNAP: 
		case TRACE_TYPE_DUCK:
		case TRACE_TYPE_80211_RADIO:
		case TRACE_TYPE_80211_PRISM:
		case TRACE_TYPE_80211:
		case TRACE_TYPE_PFLOG:
		case TRACE_TYPE_LINUX_SLL:
		case TRACE_TYPE_PPP:
		case TRACE_TYPE_POS:
		case TRACE_TYPE_METADATA:
		case TRACE_TYPE_NONDATA:
		case TRACE_TYPE_OPENBSD_LOOP:
		case TRACE_TYPE_UNKNOWN:
			break;
	}
	return 255;
}

libtrace_linktype_t arphrd_type_to_libtrace(unsigned int arphrd) {
	switch(arphrd) {
		case LIBTRACE_ARPHRD_ETHER: return TRACE_TYPE_ETH;	
		case LIBTRACE_ARPHRD_EETHER: return TRACE_TYPE_ETH;	
		case LIBTRACE_ARPHRD_IEEE80211: return TRACE_TYPE_80211;
		case LIBTRACE_ARPHRD_IEEE80211_RADIOTAP: return TRACE_TYPE_80211_RADIO;
		case LIBTRACE_ARPHRD_PPP: return TRACE_TYPE_NONE;
		case LIBTRACE_ARPHRD_LOOPBACK: return TRACE_TYPE_ETH;
		case LIBTRACE_ARPHRD_NONE: return TRACE_TYPE_NONE;
	}
	printf("Unknown ARPHRD %08x\n",arphrd);
	return ~0U;
}

unsigned int libtrace_to_arphrd_type(libtrace_linktype_t linktype) {
	switch(linktype) {
		case TRACE_TYPE_ETH: return LIBTRACE_ARPHRD_ETHER;
		case TRACE_TYPE_80211: return LIBTRACE_ARPHRD_IEEE80211;
		case TRACE_TYPE_80211_RADIO: return LIBTRACE_ARPHRD_IEEE80211_RADIOTAP;
	  	default: break;
	}
	return ~0U;
}

/** Prepends a Linux SLL header to the packet.
 * 
 * Packets that don't support direction tagging are annoying, especially
 * when we have direction tagging information!  So this converts the packet
 * to TRACE_TYPE_LINUX_SLL which does support direction tagging.  This is a
 * pcap style packet for the reason that it means it works with bpf filters.
 *
 * @note this will copy the packet, so use sparingly if possible.
 */
void promote_packet(libtrace_packet_t *packet)
{
	if (packet->trace->format->type == TRACE_FORMAT_PCAP) {
		char *tmpbuffer;
		libtrace_sll_header_t *hdr;

		if (pcap_linktype_to_libtrace(rt_to_pcap_linktype(packet->type))
			== TRACE_TYPE_LINUX_SLL) {
			/* This is already been promoted, so ignore it */
			return;
		}

		/* This should be easy, just prepend the header */
		tmpbuffer= (char*)malloc(
				sizeof(libtrace_sll_header_t)
				+trace_get_capture_length(packet)
				+trace_get_framing_length(packet)
				);

		hdr=(libtrace_sll_header_t*)((char*)tmpbuffer
			+trace_get_framing_length(packet));

		hdr->halen=htons(6);
		hdr->pkttype=TRACE_SLL_OUTGOING;

		switch(pcap_linktype_to_libtrace(rt_to_pcap_linktype(packet->type))) {
			case TRACE_TYPE_NONE:
				trace_get_layer3(packet, &hdr->protocol, NULL);
				hdr->hatype = htons(LIBTRACE_ARPHRD_PPP);
				hdr->protocol=htons(hdr->protocol);
				break;
			case TRACE_TYPE_ETH:
				hdr->hatype = htons(LIBTRACE_ARPHRD_ETHER);
				hdr->protocol=htons(0x0060); /* ETH_P_LOOP */
				break;
			default:
				/* failed */
				return;
		}
		memcpy(tmpbuffer,packet->header,
				trace_get_framing_length(packet));
		memcpy(tmpbuffer
				+sizeof(libtrace_sll_header_t)
				+trace_get_framing_length(packet),
				packet->payload,
				trace_get_capture_length(packet));
		if (packet->buf_control == TRACE_CTRL_EXTERNAL) {
			packet->buf_control=TRACE_CTRL_PACKET;
		}
		else {
			free(packet->buffer);
		}
		packet->buffer=tmpbuffer;
		packet->header=tmpbuffer;
		packet->payload=tmpbuffer+trace_get_framing_length(packet);
		packet->type=pcap_linktype_to_rt(TRACE_DLT_LINUX_SLL);
		((struct libtrace_pcapfile_pkt_hdr_t*) packet->header)->caplen+=
			sizeof(libtrace_sll_header_t);
		((struct libtrace_pcapfile_pkt_hdr_t*) packet->header)->wirelen+=
			sizeof(libtrace_sll_header_t);
		trace_clear_cache(packet);
		return;
	}
}

/* Try and remove any extraneous encapsulation that may have been added to
 * a packet. Effectively the opposite to promote_packet.
 *
 * Returns true if demotion was possible, false if not.
 */
bool demote_packet(libtrace_packet_t *packet)
{
	uint8_t type;
	uint16_t ha_type, next_proto;
	libtrace_sll_header_t *sll = NULL;
	uint32_t remaining = 0;
	char *tmp;
	struct timeval tv;
	static libtrace_t *trace = NULL;
	switch(trace_get_link_type(packet)) {
		case TRACE_TYPE_ATM:
			remaining=trace_get_capture_length(packet);
			packet->payload=trace_get_payload_from_atm(
				packet->payload,&type,&remaining);
			if (!packet->payload)
				return false;
			tmp=(char*)malloc(
				trace_get_capture_length(packet)
				+sizeof(libtrace_pcapfile_pkt_hdr_t)
				);

			tv=trace_get_timeval(packet);
			((libtrace_pcapfile_pkt_hdr_t*)tmp)->ts_sec=tv.tv_sec;
			((libtrace_pcapfile_pkt_hdr_t*)tmp)->ts_usec=tv.tv_usec;
			((libtrace_pcapfile_pkt_hdr_t*)tmp)->wirelen
				= trace_get_wire_length(packet)-(trace_get_capture_length(packet)-remaining);
			((libtrace_pcapfile_pkt_hdr_t*)tmp)->caplen
				= remaining;

			memcpy(tmp+sizeof(libtrace_pcapfile_pkt_hdr_t),
					packet->payload,
					(size_t)remaining);
			if (packet->buf_control == TRACE_CTRL_EXTERNAL) {
				packet->buf_control=TRACE_CTRL_PACKET;
			}
			else {
				free(packet->buffer);
			}
			packet->buffer=tmp;
			packet->header=tmp;
			packet->payload=tmp+sizeof(libtrace_pcapfile_pkt_hdr_t);
			packet->type=pcap_linktype_to_rt(TRACE_DLT_ATM_RFC1483);
			
			if (trace == NULL) {
				trace = trace_create_dead("pcapfile:-");
			}

			packet->trace=trace;

			/* Invalidate caches */
			trace_clear_cache(packet);
			return true;

		case TRACE_TYPE_LINUX_SLL:
			sll = (libtrace_sll_header_t *)(packet->payload);

			ha_type = ntohs(sll->hatype);
			next_proto = ntohs(sll->protocol);
		
			/* Preserved from older libtrace behaviour */
			if (ha_type == LIBTRACE_ARPHRD_PPP)
				packet->type = pcap_linktype_to_rt(TRACE_DLT_RAW);
			/* Don't decide trace type based on ha_type,
			 * decide based on the protocol header that is
			 * coming up!
			 */
			else if (next_proto == TRACE_ETHERTYPE_LOOPBACK)
				packet->type = pcap_linktype_to_rt(TRACE_DLT_EN10MB);
			else if (next_proto == TRACE_ETHERTYPE_IP) 
				packet->type = pcap_linktype_to_rt(TRACE_DLT_RAW);
			else if (next_proto == TRACE_ETHERTYPE_IPV6)
				packet->type = pcap_linktype_to_rt(TRACE_DLT_RAW);
			else
				return false;

			/* Skip the Linux SLL header */
			packet->payload=(void*)((char*)packet->payload
					+sizeof(libtrace_sll_header_t));
			trace_set_capture_length(packet,
				trace_get_capture_length(packet)
					-sizeof(libtrace_sll_header_t));

			/* Invalidate caches */
			trace_clear_cache(packet);
			break;
		default:
			return false;
	}

	/* Invalidate caches */
	trace_clear_cache(packet);
	return true;
}
