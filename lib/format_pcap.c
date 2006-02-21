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
#include "libtrace_int.h"
#include "format_helper.h"

#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#else
#  error "Can't find inttypes.h - this needs to be fixed"
#endif 

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

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
static struct libtrace_format_t pcap;
static struct libtrace_format_t pcapint;

#define DATA(x) ((struct libtrace_format_data_t*)((x)->format_data))

#define INPUT libtrace->format_data->input
#define OUTPUT libtrace->format_data->output
struct libtrace_format_data_t {
	union {
                char *path;		/**< information for local sockets */
                char *interface;	/**< intormation for reading of network
					     interfaces */
        } conn_info;
	/** Information about the current state of the input device */
        union {
                pcap_t *pcap;
        } input;
	int snaplen;
	libtrace_filter_t *filter;
	int promisc;
};

struct libtrace_format_data_out_t {
	union {
		char *path;
		char *interface;
	} conn_info;
	union {
		struct {
			pcap_t *pcap;
			pcap_dumper_t *dump;
		} trace;

	} output;
};

static int pcap_init_input(struct libtrace_t *libtrace) {
	libtrace->format_data = (struct libtrace_format_data_t *) 
		malloc(sizeof(struct libtrace_format_data_t));

	INPUT.pcap = NULL;
	DATA(libtrace)->filter = NULL;
	DATA(libtrace)->snaplen = 0;
	DATA(libtrace)->promisc = 0;

	return 1;
}

static int pcap_start_input(struct libtrace_t *libtrace) {
	char errbuf[PCAP_ERRBUF_SIZE];
	if ((INPUT.pcap = 
		pcap_open_offline(libtrace->uridata,
			errbuf)) == NULL) {
		trace_set_err(TRACE_ERR_INIT_FAILED,"%s",
				errbuf);
		return -1;
	}
	if (DATA(libtrace)->filter) {
		trace_bpf_compile(DATA(libtrace)->filter);
		if (pcap_setfilter(INPUT.pcap,&DATA(libtrace)->filter->filter) 
				== -1) {
			trace_set_err(TRACE_ERR_INIT_FAILED,"%s",
					pcap_geterr(INPUT.pcap));
			return -1;
		}
	}
	return 0;
}

static int pcap_config_input(libtrace_t *libtrace,
		trace_option_t option,
		void *data)
{
	switch(option) {
		case TRACE_OPTION_FILTER:
			DATA(libtrace)->filter=data;
			return 0;
		case TRACE_OPTION_SNAPLEN:
			/* Snapping isn't supported directly, so fall thru
			 * and let libtrace deal with it
			 */
		case TRACE_OPTION_PROMISC:
			/* can't do promisc on a trace! fall thru */
		default:
			trace_set_err(TRACE_ERR_UNKNOWN_OPTION,
					"Unknown option %i", option);
			return -1;
	}
	assert(0);
}

static int pcap_pause_input(libtrace_t *libtrace) {
	pcap_close(INPUT.pcap);
	INPUT.pcap=NULL;
}

static int pcap_init_output(struct libtrace_out_t *libtrace) {
	libtrace->format_data = (struct libtrace_format_data_out_t *)
		malloc(sizeof(struct libtrace_format_data_out_t));
	OUTPUT.trace.pcap = NULL;
	OUTPUT.trace.dump = NULL;
	return 1;
}

static int pcapint_init_input(struct libtrace_t *libtrace) {
	libtrace->format_data = (struct libtrace_format_data_t *) 
		malloc(sizeof(struct libtrace_format_data_t));
	DATA(libtrace)->filter = NULL;
	DATA(libtrace)->snaplen = 0;
	DATA(libtrace)->promisc = 0;
	return 1;
}

static int pcapint_config_input(libtrace_t *libtrace,
		trace_option_t option,
		void *data)
{
	switch(option) {
		case TRACE_OPTION_FILTER:
			DATA(libtrace)->filter=data;
			return 0;
		case TRACE_OPTION_SNAPLEN:
			DATA(libtrace)->snaplen=*(int*)data;
			return 0;
		case TRACE_OPTION_PROMISC:
			DATA(libtrace)->promisc=*(int*)data;
			return 0;
		default:
			trace_set_err(TRACE_ERR_UNKNOWN_OPTION,
					"Unknown option %i", option);
			return -1;
	}
	assert(0);
}

static int pcapint_start_input(libtrace_t *libtrace) {
	char errbuf[PCAP_ERRBUF_SIZE];
	if ((INPUT.pcap = 
			pcap_open_live(libtrace->uridata,
			DATA(libtrace)->snaplen,
			DATA(libtrace)->promisc,
			1,
			errbuf)) == NULL) {
		trace_set_err(TRACE_ERR_INIT_FAILED,"%s",errbuf);
		/* Set a filter if one is defined */
		if (DATA(libtrace)->filter)
			if (pcap_setfilter(INPUT.pcap,&DATA(libtrace)->filter->filter)
				== -1) {
				trace_set_err(TRACE_ERR_INIT_FAILED,"%s",
						pcap_geterr(INPUT.pcap));
				return -1;
			}
		return 0;
	}
	return 1;
}

static int pcapint_init_output(struct libtrace_out_t *libtrace __attribute__((unused))) {
	trace_set_err(TRACE_ERR_NO_INIT_OUT,"Writing to a pcap interface not implemented yet");
	return -1;
}

static int pcap_fin_input(struct libtrace_t *libtrace) {
	pcap_close(INPUT.pcap);
	free(libtrace->format_data);
	return 0;
}

static int pcap_fin_output(struct libtrace_out_t *libtrace) {
	pcap_dump_flush(OUTPUT.trace.dump);
	pcap_dump_close(OUTPUT.trace.dump);
	return 0;
}

static int pcapint_fin_output(struct libtrace_out_t *libtrace __attribute__((unused))) {
	return -1;
}

static void trace_pcap_handler(u_char *user, const struct pcap_pkthdr *pcaphdr, const u_char *pcappkt) {
	struct libtrace_packet_t *packet = (struct libtrace_packet_t *)user;	
	int numbytes = 0;

	/*
	// pcap provides us with the right bits, in it's own buffers.
	// We hijack them.
	*/
	numbytes = pcaphdr->len;

	packet->header = (void *)pcaphdr;
	packet->payload = (void *)pcappkt;


	packet->size = numbytes + sizeof(struct pcap_pkthdr);
}

static int pcap_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	int pcapbytes = 0;

	pcapbytes = pcap_dispatch(INPUT.pcap,
					1, /* number of packets */
					&trace_pcap_handler,
					(u_char *)packet);

	if (pcapbytes <= 0) {
		return pcapbytes;
	}
	return (packet->size - sizeof(struct pcap_pkthdr));
}

static int pcap_write_packet(struct libtrace_out_t *libtrace, const struct libtrace_packet_t *packet) {
	struct pcap_pkthdr pcap_pkt_hdr;

	if (!OUTPUT.trace.pcap) {
		OUTPUT.trace.pcap = (pcap_t *)pcap_open_dead(
			libtrace_to_pcap_dlt(trace_get_link_type(packet)),
			65536);
		OUTPUT.trace.dump = pcap_dump_open(OUTPUT.trace.pcap,
				libtrace->uridata);
		fflush((FILE *)OUTPUT.trace.dump);
	}
	if (packet->trace->format == &pcap || 
			packet->trace->format == &pcapint) {
		
		pcap_dump((u_char*)OUTPUT.trace.dump,(struct pcap_pkthdr *)packet->header,packet->payload);
	} else {
		/* Leave the manual copy as it is, as it gets around 
		 * some OS's having different structures in pcap_pkt_hdr
		 */
		struct timeval ts = trace_get_timeval(packet);
		pcap_pkt_hdr.ts.tv_sec = ts.tv_sec;
		pcap_pkt_hdr.ts.tv_usec = ts.tv_usec;
		pcap_pkt_hdr.caplen = trace_get_capture_length(packet);
		pcap_pkt_hdr.len = trace_get_wire_length(packet);

		pcap_dump((u_char*)OUTPUT.trace.dump, &pcap_pkt_hdr, packet->payload);
	}
	return 0;
}

static int pcapint_write_packet(struct libtrace_out_t *libtrace __attribute__((unused)), const struct libtrace_packet_t *packet __attribute__((unused))) {

	assert(0);
	return 0;
}

static libtrace_linktype_t pcap_get_link_type(const struct libtrace_packet_t *packet) {
	struct pcap_pkthdr *pcapptr = 0;
	int linktype = 0;
	pcapptr = (struct pcap_pkthdr *)packet->header;
	linktype = pcap_datalink(packet->trace->format_data->input.pcap);
	return pcap_dlt_to_libtrace(linktype);
}

static int8_t pcap_get_direction(const struct libtrace_packet_t *packet) {
	int8_t direction  = -1;
	switch(pcap_get_link_type(packet)) {
		case TRACE_TYPE_LINUX_SLL:
		{
			struct trace_sll_header_t *sll;
			sll = trace_get_link(packet);
			if (!sll) {
				trace_set_err(TRACE_ERR_BAD_PACKET,
						"Bad or missing packet");
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
				trace_set_err(TRACE_ERR_BAD_PACKET,
						"Bad or missing packet");
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
	struct pcap_pkthdr *pcapptr = (struct pcap_pkthdr *)packet->header;
	struct timeval ts;
	ts.tv_sec = pcapptr->ts.tv_sec;
	ts.tv_usec = pcapptr->ts.tv_usec;
	return ts;
}


static int pcap_get_capture_length(const struct libtrace_packet_t *packet) {
	struct pcap_pkthdr *pcapptr = 0;
	pcapptr = (struct pcap_pkthdr *)packet->header;
	return pcapptr->caplen;
}

static int pcap_get_wire_length(const struct libtrace_packet_t *packet) {
	struct pcap_pkthdr *pcapptr = 0;
	pcapptr = (struct pcap_pkthdr *)packet->header;
	return ntohs(pcapptr->len);
}

static int pcap_get_framing_length(const struct libtrace_packet_t *packet UNUSED) {
	return sizeof(struct pcap_pkthdr);
}

static size_t pcap_set_capture_length(struct libtrace_packet_t *packet,size_t size) {
	struct pcap_pkthdr *pcapptr = 0;
	assert(packet);
	if ((size + sizeof(struct pcap_pkthdr)) > packet->size) {
		/* can't make a packet larger */
		return (packet->size - sizeof(struct pcap_pkthdr));
	}
	pcapptr = (struct pcap_pkthdr *)packet->header;
	pcapptr->caplen = size;
	packet->size = size + sizeof(struct pcap_pkthdr);
	return packet->size;
}

static int pcap_get_fd(const struct libtrace_packet_t *packet) {
	return pcap_fileno(packet->trace->format_data->input.pcap);
}

static void pcap_help() {
	printf("pcap format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\tpcap:/path/to/file\n");
	printf("\n");
	printf("\te.g.: pcap:/tmp/trace.pcap\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\tnone\n");
	printf("\n");
}

static void pcapint_help() {
	printf("pcapint format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\tpcapint:interface\n");
	printf("\n");
	printf("\te.g.: pcapint:eth0\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\tnone\n");
	printf("\n");
}


static struct libtrace_format_t pcap = {
	"pcap",
	"$Id$",
	TRACE_FORMAT_PCAP,
	pcap_init_input,		/* init_input */
	NULL,				/* config_input */
	pcap_start_input,		/* start_input */
	pcap_pause_input,		/* pause_input */
	pcap_init_output,		/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	pcap_fin_input,			/* fin_input */
	pcap_fin_output,		/* fin_output */
	pcap_read_packet,		/* read_packet */
	pcap_write_packet,		/* write_packet */
	pcap_get_link_type,		/* get_link_type */
	pcap_get_direction,		/* get_direction */
	NULL,				/* set_direction */
	NULL,				/* get_erf_timestamp */
	pcap_get_timeval,		/* get_timeval */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	pcap_get_capture_length,	/* get_capture_length */
	pcap_get_wire_length,		/* get_wire_length */
	pcap_get_framing_length,	/* get_framing_length */
	pcap_set_capture_length,	/* set_capture_length */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	pcap_help			/* help */
};

static struct libtrace_format_t pcapint = {
	"pcapint",
	"$Id$",
	TRACE_FORMAT_PCAP,
	pcapint_init_input,		/* init_input */
	pcapint_config_input,		/* config_input */
	pcapint_start_input,		/* start_input */
	pcap_pause_input,		/* pause_input */
	pcapint_init_output,		/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	pcap_fin_input,			/* fin_input */
	pcapint_fin_output,		/* fin_output */
	pcap_read_packet,		/* read_packet */
	pcapint_write_packet,		/* write_packet */
	pcap_get_link_type,		/* get_link_type */
	pcap_get_direction,		/* get_direction */
	NULL,				/* set_direction */
	NULL,				/* get_erf_timestamp */
	pcap_get_timeval,		/* get_timeval */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	pcap_get_capture_length,	/* get_capture_length */
	pcap_get_wire_length,		/* get_wire_length */
	pcap_get_framing_length,	/* get_framing_length */
	pcap_set_capture_length,	/* set_capture_length */
	pcap_get_fd,			/* get_fd */
	trace_event_device,		/* trace_event */
	pcapint_help			/* help */
};

void __attribute__((constructor)) pcap_constructor() {
	register_format(&pcap);
	register_format(&pcapint);
}


#endif
