#include "libtrace.h"
#include "config.h"

#include "rt_protocol.h"
#include <assert.h>
#include "libtrace_int.h"
#include <stdlib.h>
#include <string.h>

#ifndef WIN32
#include <net/if_arp.h>
#endif

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER    1               /* Ethernet 10/100Mbps.  */
#endif

#ifndef ARPHRD_PPP
#define ARPHRD_PPP      512
#endif

#ifndef ARPHRD_IEEE80211
#define ARPHRD_IEEE80211	801
#endif


/* This file maps libtrace types to/from pcap DLT and erf types
 *
 * When adding a new linktype to libtrace, add the mapping(s) here,
 * and add the understanding of the type to get_ip(), and perhaps
 * get_{source,destination}_mac (if your linklayer has mac's)
 */

libtrace_linktype_t pcap_dlt_to_libtrace(libtrace_dlt_t dlt)
{
	switch(dlt) {
		case TRACE_DLT_RAW: return TRACE_TYPE_NONE;
		case TRACE_DLT_EN10MB: return TRACE_TYPE_ETH;
		case TRACE_DLT_IEEE802_11: return TRACE_TYPE_80211;
		case TRACE_DLT_LINUX_SLL: return TRACE_TYPE_LINUX_SLL;
		case TRACE_DLT_PFLOG: return TRACE_TYPE_PFLOG;
        	case TRACE_DLT_IEEE802_11_RADIO: return TRACE_TYPE_80211_RADIO;
		case TRACE_DLT_ATM_RFC1483: return TRACE_TYPE_LLCSNAP;
					 
	}
	return ~0;
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
		case TRACE_TYPE_ATM: 
			/* Dispite hints to the contrary, there is no DLT
			 * for 'raw atm packets that happen to be missing
			 * the HEC' or even 'raw atm packets that have a hec'.
			 *
			 * The closest are DLT_ATM_RFC1483 but that doesn't
			 * include the ATM header, only the LLCSNAP header.
			 */
			return ~0;
		case TRACE_TYPE_LLCSNAP: return TRACE_DLT_ATM_RFC1483;
	}
	return ~0;
}

enum rt_field_t pcap_dlt_to_rt(libtrace_dlt_t dlt) 
{
	/* For pcap the rt type is just the dlt + a fixed value */
	return dlt + RT_DATA_PCAP;
}

libtrace_dlt_t rt_to_pcap_dlt(enum rt_field_t rt_type)
{
	assert(rt_type >= RT_DATA_PCAP);
	return rt_type - RT_DATA_PCAP;
}

libtrace_linktype_t erf_type_to_libtrace(char erf)
{
	switch (erf) {
		case TYPE_HDLC_POS:	return TRACE_TYPE_HDLC_POS;
		case TYPE_ETH:		return TRACE_TYPE_ETH;
		case TYPE_ATM:		return TRACE_TYPE_ATM;
		case TYPE_AAL5:		return TRACE_TYPE_AAL5;
	}
	return ~0;
}

char libtrace_to_erf_type(libtrace_linktype_t linktype)
{
	switch(linktype) {
		case TRACE_TYPE_HDLC_POS: return TYPE_HDLC_POS;
		case TRACE_TYPE_ETH:	return TYPE_ETH;
		case TRACE_TYPE_ATM:	return TYPE_ATM;
		case TRACE_TYPE_AAL5:	return TYPE_AAL5;
	}
	return -1;
}

libtrace_linktype_t arphrd_type_to_libtrace(unsigned int arphrd) {
	switch(arphrd) {
		case ARPHRD_ETHER: return TRACE_TYPE_ETH;	
		case ARPHRD_IEEE80211: return TRACE_TYPE_80211;
		case ARPHRD_80211_RADIOTAP: return TRACE_TYPE_80211_RADIO;
	}
	return ~0;
}

unsigned int libtrace_to_arphrd_type(libtrace_linktype_t linktype) {
	switch(linktype) {
		case TRACE_TYPE_ETH: return ARPHRD_ETHER;
		case TRACE_TYPE_80211: return ARPHRD_IEEE80211;
		case TRACE_TYPE_80211_RADIO: return ARPHRD_80211_RADIOTAP;
	}
	return -1;
}

/** Tinker with a packet
 * packets that don't support direction tagging are annoying, especially
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

		if (pcap_dlt_to_libtrace(rt_to_pcap_dlt(packet->type))
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

		switch(pcap_dlt_to_libtrace(rt_to_pcap_dlt(packet->type))) {
			case TRACE_TYPE_NONE:
				trace_get_payload_from_link(
					trace_get_link(packet),
					trace_get_link_type(packet),
					&hdr->protocol,
					NULL);
				hdr->hatype = htons(ARPHRD_PPP);
				hdr->protocol=htons(hdr->protocol);
				break;
			case TRACE_TYPE_ETH:
				hdr->hatype = htons(ARPHRD_ETHER);
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
		packet->type=pcap_dlt_to_rt(TRACE_DLT_LINUX_SLL);
		((struct libtrace_pcapfile_pkt_hdr_t*) packet->header)->caplen+=
			sizeof(libtrace_sll_header_t);
		((struct libtrace_pcapfile_pkt_hdr_t*) packet->header)->wirelen+=
			sizeof(libtrace_sll_header_t);
		return;
	}
}

/* Try and simplify the packet one step, kinda the opposite to promote_packet
 *
 * returns true if demotion was possible, false if not.
 */
bool demote_packet(libtrace_packet_t *packet)
{
	uint8_t type;
	uint32_t remaining;
	char *tmp;
	struct timeval tv;
	static libtrace_t *trace = NULL;
	switch(trace_get_link_type(packet)) {
		case TRACE_TYPE_ATM:
			remaining=trace_get_capture_length(packet);
			packet->payload=trace_get_payload_from_atm(
				packet->payload,&type,&remaining);

			tmp=malloc(
				trace_get_capture_length(packet)
				+sizeof(libtrace_pcapfile_pkt_hdr_t)
				);

			tv=trace_get_timeval(packet);
			((libtrace_pcapfile_pkt_hdr_t*)tmp)->ts_sec=tv.tv_sec;
			((libtrace_pcapfile_pkt_hdr_t*)tmp)->ts_usec=tv.tv_usec;
			((libtrace_pcapfile_pkt_hdr_t*)tmp)->caplen
				= remaining;
			((libtrace_pcapfile_pkt_hdr_t*)tmp)->wirelen
				= trace_get_capture_length(packet)-remaining;

			memcpy(tmp+sizeof(libtrace_pcapfile_pkt_hdr_t),
					packet->payload,
					remaining);
			if (packet->buf_control == TRACE_CTRL_EXTERNAL) {
				packet->buf_control=TRACE_CTRL_PACKET;
			}
			else {
				free(packet->buffer);
			}
			packet->buffer=tmp;
			packet->header=tmp;
			packet->payload=tmp+sizeof(libtrace_pcapfile_pkt_hdr_t);
			packet->type=pcap_dlt_to_rt(TRACE_DLT_ATM_RFC1483);
			
			if (trace == NULL) {
				trace = trace_create_dead("pcap:-");
			}

			packet->trace=trace;

			return true;

		case TRACE_TYPE_LINUX_SLL:
			switch(ntohs(((libtrace_sll_header_t*)packet->payload)
					->hatype)) {
				case ARPHRD_PPP:
					packet->type=pcap_dlt_to_rt(TRACE_DLT_RAW);
					break;
				case ARPHRD_ETHER:
					packet->type=pcap_dlt_to_rt(TRACE_DLT_EN10MB);
					break;
				default:
					/* Dunno how to demote this packet */
					return false;
			}
			/* Skip the Linux SLL header */
			packet->payload=(void*)((char*)packet->payload
					+sizeof(libtrace_sll_header_t));
			trace_set_capture_length(packet,
				trace_get_capture_length(packet)
					-sizeof(libtrace_sll_header_t));
			break;
		default:
			return false;
	}
	return true;
}
