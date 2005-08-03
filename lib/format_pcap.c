/*
 * This file is part of libtrace
 *
 * Copyright (c) 2004 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson 
 *          Perry Lorier 
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

#include "common.h"
#include "config.h"
#include "libtrace.h"
#include "format.h"
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>


#if HAVE_PCAP_BPF_H
#  include <pcap-bpf.h>
#else
#  ifdef HAVE_NET_BPF_H
#    include <net/bpf.h>
#  endif
#endif

#if HAVE_PCAP_H
#  include <pcap.h>
#  ifdef HAVE_PCAP_INT_H
#    include <pcap-int.h>
#  endif
#endif

#if HAVE_PCAP

static int pcap_init_input(struct libtrace_t *libtrace) {
	char errbuf[PCAP_ERRBUF_SIZE];
	struct stat buf;
	if (!strncmp(libtrace->conn_info.path,"-",1)) {
		if ((libtrace->input.pcap = 
			pcap_open_offline(libtrace->conn_info.path,
						errbuf)) == NULL) {
			fprintf(stderr,"%s\n",errbuf);
			return 0;
		}		
	} else {
		if (stat(libtrace->conn_info.path,&buf) == -1) {
			perror("stat");
			return 0;
		}
		if (S_ISCHR(buf.st_mode)) {
			if ((libtrace->input.pcap = 
				pcap_open_live(libtrace->conn_info.path,
					4096,
					1,
					1,
					errbuf)) == NULL) {
				fprintf(stderr,"%s\n",errbuf);
				return 0;
			}
		} else { 
			if ((libtrace->input.pcap = 
				pcap_open_offline(libtrace->conn_info.path,
				       	errbuf)) == NULL) {
				fprintf(stderr,"%s\n",errbuf);
				return 0;
			}
		}	
	}
	fprintf(stderr,
			"Unsupported scheme (%s) for format pcap\n",
			libtrace->conn_info.path);
	return 0;
	
}

static int pcapint_init_input(struct libtrace_t *libtrace) {
	char errbuf[PCAP_ERRBUF_SIZE];
	if ((libtrace->input.pcap = 
			pcap_open_live(libtrace->conn_info.path,
			4096,
			1,
			1,
			errbuf)) == NULL) {
		fprintf(stderr,"%s\n",errbuf);
		return 0;
	}

}

static int pcap_fin_input(struct libtrace_t *libtrace) {
	return -1;
}

static void trace_pcap_handler(u_char *user, const struct pcap_pkthdr *pcaphdr, const u_char *pcappkt) {
	struct libtrace_packet_t *packet = (struct libtrace_packet_t *)user;	
	void *buffer = packet->buffer;
	int numbytes = 0;
	
	memcpy(buffer,pcaphdr,sizeof(struct pcap_pkthdr));
	numbytes = pcaphdr->len;
	memcpy(buffer + sizeof(struct pcap_pkthdr),pcappkt,numbytes);

	packet->size = numbytes + sizeof(struct pcap_pkthdr);

}
static int pcap_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	const u_char *pcappkt;
	int pcapbytes = 0;

	while ((pcapbytes = pcap_dispatch(libtrace->input.pcap,
					1, /* number of packets */
					&trace_pcap_handler,
					(u_char *)packet)) == 0);

	if (pcapbytes < 0) {
		return -1;
	}
	return (packet->size - sizeof(struct pcap_pkthdr));
}

static void *pcap_get_link(const struct libtrace_packet_t *packet) {
	return (void *) (packet->buffer + sizeof(struct pcap_pkthdr));
}

static libtrace_linktype_t pcap_get_link_type(const struct libtrace_packet_t *packet) {
	struct pcap_pkthdr *pcapptr = 0;
	int linktype = 0;
	pcapptr = (struct pcap_pkthdr *)packet->buffer;
	linktype = pcap_datalink(packet->trace->input.pcap);
	switch(linktype) {
		case DLT_NULL:
			return TRACE_TYPE_NONE;
		case DLT_EN10MB:
			return TRACE_TYPE_ETH;
		case DLT_ATM_RFC1483:
			return TRACE_TYPE_ATM;
		case DLT_IEEE802_11:
			return TRACE_TYPE_80211;
#ifdef DLT_LINUX_SLL
		case DLT_LINUX_SLL:
			return TRACE_TYPE_LINUX_SLL;
#endif
#ifdef DLT_PFLOG
		case DLT_PFLOG:
			return TRACE_TYPE_PFLOG;
#endif
	}
	return -1;
}

static int8_t pcap_get_direction(const struct libtrace_packet_t *packet) {
	int8_t direction  = -1;
	switch(pcap_get_link_type(packet)) {
		case TRACE_TYPE_LINUX_SLL:
		{
			struct trace_sll_header_t *sll;
			sll = trace_get_link(packet);
			if (!sll) {
				return -1;
			}
			/* 0 == LINUX_SLL_HOST */
			/* the Waikato Capture point defines "packets
			 * originating locally" (ie, outbound), with a
			 * direction of 0, and "packets destined locally"
			 * (ie, inbound), with a direction of 1.
			 * This is kind-of-opposite to LINUX_SLL.
			 * We return consistent values here, however
			 *
			 * Note that in recent versions of pcap, you can
			 * use "inbound" and "outbound" on ppp in linux
			 */
			if (ntohs(sll->pkttype == 0)) {
				direction = 1;
			} else {
				direction = 0;
			}
			break;

		}
		case TRACE_TYPE_PFLOG:
		{
			struct trace_pflog_header_t *pflog;
			pflog = trace_get_link(packet);
			if (!pflog) {
				return -1;
			}
			/* enum    { PF_IN=0, PF_OUT=1 }; */
			if (ntohs(pflog->dir==0)) {

				direction = 1;
			}
			else {
				direction = 0;
			}
			break;
		}
		default:
			break;
	}	
	return direction;
}


static struct timeval pcap_get_timeval(const struct libtrace_packet_t *packet) { 
	struct pcap_pkthdr *pcapptr = (struct pcap_pkthdr *)packet->buffer;
	return pcapptr->ts;
}


static int pcap_get_capture_length(const struct libtrace_packet_t *packet) {
	struct pcap_pkthdr *pcapptr = 0;
	pcapptr = (struct pcap_pkthdr *)packet->buffer;
	return pcapptr->caplen;
}

static int pcap_get_wire_length(const struct libtrace_packet_t *packet) {
	struct pcap_pkthdr *pcapptr = 0;
	pcapptr = (struct pcap_pkthdr *)packet->buffer;
	return ntohs(pcapptr->len);
}

static size_t pcap_set_capture_length(struct libtrace_packet_t *packet,size_t size) {
	struct pcap_pkthdr *pcapptr = 0;
	assert(packet);
	if (size > packet->size) {
		// can't make a packet larger
		return packet->size;
	}
	pcapptr = (struct pcap_pkthdr *)packet->buffer;
	pcapptr->caplen = size + sizeof(struct pcap_pkthdr);
	packet->size = pcapptr->caplen;
	return packet->size;
}

static struct format_t pcap = {
	"pcap",
	"$Id$",
	pcap_init_input,		/* init_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	pcap_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	NULL,				/* read */
	pcap_read_packet,		/* read_packet */
	NULL,				/* write_packet */
	pcap_get_link,			/* get_link */
	pcap_get_link_type,		/* get_link_type */
	pcap_get_direction,		/* get_direction */
	NULL,				/* set_direction */
	NULL,				/* get_erf_timestamp */
	pcap_get_timeval,		/* get_timeval */
	NULL,				/* get_seconds */
	pcap_get_capture_length,	/* get_capture_length */
	pcap_get_wire_length,		/* get_wire_length */
	pcap_set_capture_length		/* set_capture_length */
};

static struct format_t pcapint = {
	"pcapint",
	"$Id$",
	pcapint_init_input,		/* init_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	pcap_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	NULL,				/* read */
	pcap_read_packet,		/* read_packet */
	NULL,				/* write_packet */
	pcap_get_link,			/* get_link */
	pcap_get_link_type,		/* get_link_type */
	pcap_get_direction,		/* get_direction */
	NULL,				/* set_direction */
	NULL,				/* get_erf_timestamp */
	pcap_get_timeval,		/* get_timeval */
	NULL,				/* get_seconds */
	pcap_get_capture_length,	/* get_capture_length */
	pcap_get_wire_length,		/* get_wire_length */
	pcap_set_capture_length		/* set_capture_length */
};

void __attribute__((constructor)) pcap_constructor() {
	register_format(&pcap);
	register_format(&pcapint);
}


#endif
