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

#include <sys/stat.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_PCAP_H
#  include <pcap.h>
#  ifdef HAVE_PCAP_INT_H
#    include <pcap-int.h>
#  endif
#endif

#ifdef HAVE_LIBPCAP
static struct libtrace_format_t pcap;
static struct libtrace_format_t pcapint;

#define DATA(x) ((struct pcap_format_data_t*)((x)->format_data))
#define DATAOUT(x) ((struct pcap_format_data_out_t*)((x)->format_data))

#define INPUT DATA(libtrace)->input
#define OUTPUT DATAOUT(libtrace)->output
struct pcap_format_data_t {
	/** Information about the current state of the input device */
        union {
                pcap_t *pcap;
        } input;
	int snaplen;
	libtrace_filter_t *filter;
	int promisc;
};

struct pcap_format_data_out_t {
	union {
		struct {
			pcap_t *pcap;
			pcap_dumper_t *dump;
		} trace;

	} output;
};

static int pcap_init_input(libtrace_t *libtrace) {
	libtrace->format_data = malloc(sizeof(struct pcap_format_data_t));

	INPUT.pcap = NULL;
	DATA(libtrace)->filter = NULL;
	DATA(libtrace)->snaplen = LIBTRACE_PACKET_BUFSIZE;
	DATA(libtrace)->promisc = 0;

	return 0;
}

static int pcap_start_input(libtrace_t *libtrace) {
	char errbuf[PCAP_ERRBUF_SIZE];

	/* if the file is already open */
	if (INPUT.pcap)
		return 0; /* success */

	if ((INPUT.pcap = 
		pcap_open_offline(libtrace->uridata,
			errbuf)) == NULL) {
		trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"%s",
				errbuf);
		return -1;
	}
	if (DATA(libtrace)->filter) {
		pcap_compile(INPUT.pcap, &DATA(libtrace)->filter->filter,
				DATA(libtrace)->filter->filterstring, 1, 0);
		if (pcap_setfilter(INPUT.pcap,&DATA(libtrace)->filter->filter) 
				== -1) {
			trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"%s",
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
		case TRACE_META_FREQ:
			/* No meta data for this format */
		default:
			trace_set_err(libtrace,TRACE_ERR_UNKNOWN_OPTION,
					"Unknown option %i", option);
			return -1;
	}
	assert(0);
}

static int pcap_init_output(libtrace_out_t *libtrace) {
	libtrace->format_data = malloc(sizeof(struct pcap_format_data_out_t));
	OUTPUT.trace.pcap = NULL;
	OUTPUT.trace.dump = NULL;
	return 0;
}

static int pcapint_init_output(libtrace_out_t *libtrace) {
#ifdef HAVE_PCAP_INJECT
	libtrace->format_data = malloc(sizeof(struct pcap_format_data_out_t));
	OUTPUT.trace.pcap = NULL;
	OUTPUT.trace.dump = NULL;
	return 0;
#else
#ifdef HAVE_PCAP_SENDPACKET
	libtrace->format_data = malloc(sizeof(struct pcap_format_data_out_t));
	OUTPUT.trace.pcap = NULL;
	OUTPUT.trace.dump = NULL;
	return 0;
#else
	trace_set_err_out(libtrace,TRACE_ERR_UNSUPPORTED,
			"writing not supported by this version of pcap");
	return -1;
#endif
#endif
}

static int pcapint_init_input(libtrace_t *libtrace) {
	libtrace->format_data = malloc(sizeof(struct pcap_format_data_t));
	DATA(libtrace)->filter = NULL;
	DATA(libtrace)->snaplen = LIBTRACE_PACKET_BUFSIZE;
	DATA(libtrace)->promisc = 0;
	return 0; /* success */
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
		case TRACE_META_FREQ:
			/* No meta-data for this format */
		default:
			trace_set_err(libtrace,TRACE_ERR_UNKNOWN_OPTION,
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
		trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"%s",errbuf);
		return -1; /* failure */
	}
	/* Set a filter if one is defined */
	if (DATA(libtrace)->filter) {
		if (pcap_setfilter(INPUT.pcap,&DATA(libtrace)->filter->filter)
			== -1) {
			trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"%s",
					pcap_geterr(INPUT.pcap));
			return -1; /* failure */
		}
	}
#ifdef HAVE_PCAP_SETNONBLOCK
	pcap_setnonblock(INPUT.pcap,0,errbuf);
#endif
	return 0; /* success */
}

static int pcap_pause_input(libtrace_t *libtrace)
{
	pcap_close(INPUT.pcap);
	INPUT.pcap=NULL;
	return 0; /* success */
}


static int pcap_fin_input(libtrace_t *libtrace) 
{
	free(libtrace->format_data);
	return 0; /* success */
}

static int pcap_fin_output(libtrace_out_t *libtrace) 
{
	if (OUTPUT.trace.dump) {
		pcap_dump_flush(OUTPUT.trace.dump);
		pcap_dump_close(OUTPUT.trace.dump);
	}
	pcap_close(OUTPUT.trace.pcap);
	free(libtrace->format_data);
	return 0;
}

static int pcapint_fin_output(libtrace_out_t *libtrace)
{
	pcap_close(OUTPUT.trace.pcap);
	free(libtrace->format_data);
	return 0;
}


static int pcap_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	int ret = 0;
	int linktype;

	assert(libtrace->format_data);
	linktype = pcap_datalink(DATA(libtrace)->input.pcap);
	packet->type = pcap_dlt_to_rt(linktype);

	packet->buf_control = TRACE_CTRL_PACKET;

	/* If we're using the replacement pcap_next_ex() we need to
	 * make sure we have a buffer to *shudder* memcpy into 
	 */
	if (!packet->buffer) {
		packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
		if (!packet->buffer) {
			trace_set_err(libtrace, errno, 
					"Cannot allocate memory");
			return -1;
		}
			
		packet->header = packet->buffer;
		packet->payload = (char *)packet->buffer + 
					sizeof(struct pcap_pkthdr);
	}
	
	for(;;) {

		ret=pcap_next_ex(INPUT.pcap, 
				(struct pcap_pkthdr **)&packet->header,
				(const u_char **)&packet->payload);

		switch(ret) {
			case 1: break; /* no error */
			case 0: continue; /* timeout expired */
			case -1: 
				trace_set_err(libtrace,TRACE_ERR_BAD_PACKET,
						"%s",pcap_geterr(INPUT.pcap));
				return -1; /* Error */
			case -2:
				return 0; /* EOF */
		}

		return ((struct pcap_pkthdr*)packet->header)->len
			+sizeof(struct pcap_pkthdr);
	}
}

static int pcap_write_packet(libtrace_out_t *libtrace, const libtrace_packet_t *packet) {
	struct pcap_pkthdr pcap_pkt_hdr;

	if (!OUTPUT.trace.pcap) {
		OUTPUT.trace.pcap = (pcap_t *)pcap_open_dead(
			libtrace_to_pcap_dlt(trace_get_link_type(packet)),
			65536);
		if (!OUTPUT.trace.pcap) {
			trace_set_err_out(libtrace,TRACE_ERR_INIT_FAILED,"Failed to open dead trace: %s\n",
					pcap_geterr(OUTPUT.trace.pcap));
		}
		OUTPUT.trace.dump = pcap_dump_open(OUTPUT.trace.pcap,
				libtrace->uridata);
		if (!OUTPUT.trace.dump) {
			char *errmsg = pcap_geterr(OUTPUT.trace.pcap);
			trace_set_err_out(libtrace,TRACE_ERR_INIT_FAILED,"Failed to open output file: %s\n",
					errmsg ? errmsg : "Unknown error");
			return -1;
		}
	}

	/* Corrupt packet, or other "non data" packet, so skip it */
	if (trace_get_link(packet) == NULL) {
		/* Return "success", but nothing written */
		return 0;
	}

	if (packet->trace->format == &pcap || 
			packet->trace->format == &pcapint) {
		pcap_dump((u_char*)OUTPUT.trace.dump,
				(struct pcap_pkthdr *)packet->header,
				packet->payload);
	} else {
		/* Leave the manual copy as it is, as it gets around 
		 * some OS's having different structures in pcap_pkt_hdr
		 */
		struct timeval ts = trace_get_timeval(packet);
		pcap_pkt_hdr.ts.tv_sec = ts.tv_sec;
		pcap_pkt_hdr.ts.tv_usec = ts.tv_usec;
		pcap_pkt_hdr.caplen = trace_get_capture_length(packet);
		/* trace_get_wire_length includes FCS, while pcap doesn't */
		if (trace_get_link_type(packet)==TRACE_TYPE_ETH)
			if (trace_get_wire_length(packet) >= 4) { 
				pcap_pkt_hdr.len = 
					trace_get_wire_length(packet)-4;
			}
			else {
				pcap_pkt_hdr.len = 0;
			}
		else
			pcap_pkt_hdr.len = trace_get_wire_length(packet);

		assert(pcap_pkt_hdr.caplen<65536);
		assert(pcap_pkt_hdr.len<65536);

		pcap_dump((u_char*)OUTPUT.trace.dump, &pcap_pkt_hdr, packet->payload);
	}
	return 0;
}

static int pcapint_write_packet(libtrace_out_t *libtrace, const libtrace_packet_t *packet) {
	int err;

	if (!OUTPUT.trace.pcap) {
		OUTPUT.trace.pcap = (pcap_t *)pcap_open_live(
			libtrace->uridata,65536,0,0,NULL);
	}
#ifdef HAVE_PCAP_INJECT
	err=pcap_inject(OUTPUT.trace.pcap,
			packet->payload,
			trace_get_capture_length(packet));
	if (err!=(int)trace_get_capture_length(packet))
		err=-1;
#else 
#ifdef HAVE_PCAP_SENDPACKET
	err=pcap_sendpacket(OUTPUT.trace.pcap,
			packet->payload,
			trace_get_capture_length(packet));
#endif
#endif
	return err;
}

static libtrace_linktype_t pcap_get_link_type(const libtrace_packet_t *packet) {
	/* pcap doesn't store dlt in the framing header so we need
	 * rt to do it for us 
	 */
	int linktype = rt_to_pcap_dlt(packet->type);
	return pcap_dlt_to_libtrace(linktype);
}

static libtrace_direction_t pcap_set_direction(libtrace_packet_t *packet,
		libtrace_direction_t dir) {
	libtrace_sll_header_t *sll;
	promote_packet(packet);
	sll=packet->payload;
	/* sll->pkttype should be in the endianness of the host that the
	 * trace was taken on.  this is impossible to achieve
	 * so we assume host endianness
	 */
	if(dir==TRACE_DIR_OUTGOING)
		sll->pkttype=TRACE_SLL_OUTGOING;
	else
		sll->pkttype=TRACE_SLL_HOST;
	return dir;
}

static libtrace_direction_t pcap_get_direction(const libtrace_packet_t *packet) {
	libtrace_direction_t direction  = -1;
	switch(pcap_get_link_type(packet)) {
		case TRACE_TYPE_LINUX_SLL:
		{
			libtrace_sll_header_t *sll;
			sll = trace_get_link(packet);
			if (!sll) {
				trace_set_err(packet->trace,
					TRACE_ERR_BAD_PACKET,
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
			if (sll->pkttype == TRACE_SLL_OUTGOING) {
				direction = TRACE_DIR_OUTGOING;
			} else {
				direction = TRACE_DIR_INCOMING;
			}
			break;

		}
		case TRACE_TYPE_PFLOG:
		{
			libtrace_pflog_header_t *pflog;
			pflog = trace_get_link(packet);
			if (!pflog) {
				trace_set_err(packet->trace,
						TRACE_ERR_BAD_PACKET,
						"Bad or missing packet");
				return -1;
			}
			/* enum    { PF_IN=0, PF_OUT=1 }; */
			if (ntohs(pflog->dir==0)) {

				direction = TRACE_DIR_INCOMING;
			}
			else {
				direction = TRACE_DIR_OUTGOING;
			}
			break;
		}
		default:
			break;
	}	
	return direction;
}


static struct timeval pcap_get_timeval(const libtrace_packet_t *packet) {
	struct pcap_pkthdr *pcapptr = (struct pcap_pkthdr *)packet->header;
	struct timeval ts;
	ts.tv_sec = pcapptr->ts.tv_sec;
	ts.tv_usec = pcapptr->ts.tv_usec;
	return ts;
}


static int pcap_get_capture_length(const libtrace_packet_t *packet) {
	struct pcap_pkthdr *pcapptr = 0;
	pcapptr = (struct pcap_pkthdr *)packet->header;
	assert(pcapptr->caplen<=65536);

	return pcapptr->caplen;
}

static int pcap_get_wire_length(const libtrace_packet_t *packet) {
	struct pcap_pkthdr *pcapptr = 0;
	pcapptr = (struct pcap_pkthdr *)packet->header;
	if (packet->type==pcap_dlt_to_rt(TRACE_DLT_EN10MB))
		return pcapptr->len+4; /* Include the missing FCS */
	else
		return pcapptr->len;
}

static int pcap_get_framing_length(const libtrace_packet_t *packet UNUSED) {
	return sizeof(struct pcap_pkthdr);
}

static size_t pcap_set_capture_length(libtrace_packet_t *packet,size_t size) {
	struct pcap_pkthdr *pcapptr = 0;
	assert(packet);
	if (size > trace_get_capture_length(packet)) {
		/* can't make a packet larger */
		return trace_get_capture_length(packet);
	}
	pcapptr = (struct pcap_pkthdr *)packet->header;
	pcapptr->caplen = size;
	return trace_get_capture_length(packet);
}

static int pcap_get_fd(const libtrace_t *trace) {

	assert(trace->format_data);
	return pcap_fileno(DATA(trace)->input.pcap);
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
	pcap_config_input,		/* config_input */
	pcap_start_input,		/* start_input */
	NULL,				/* pause_input */
	pcap_init_output,		/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	pcap_fin_input,			/* fin_input */
	pcap_fin_output,		/* fin_output */
	pcap_read_packet,		/* read_packet */
	NULL,				/* fin_packet */
	pcap_write_packet,		/* write_packet */
	pcap_get_link_type,		/* get_link_type */
	pcap_get_direction,		/* get_direction */
	pcap_set_direction,		/* set_direction */
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
	pcap_help,			/* help */
	NULL				/* next pointer */
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
	NULL,				/* fin_packet */
	pcapint_write_packet,		/* write_packet */
	pcap_get_link_type,		/* get_link_type */
	pcap_get_direction,		/* get_direction */
	pcap_set_direction,		/* set_direction */
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
	pcapint_help,			/* help */
	NULL				/* next pointer */
};

void pcap_constructor() {
	register_format(&pcap);
	register_format(&pcapint);
}


#endif
