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

#define DATA(x) ((struct pcapfile_format_data_t*)((x)->format_data))

typedef struct pcapfile_header_t {
		uint32_t magic_number;   /* magic number */
		uint16_t version_major;  /* major version number */
		uint16_t version_minor;  /* minor version number */
		int32_t  thiszone;       /* GMT to local correction */
		uint32_t sigfigs;        /* timestamp accuracy */
		uint32_t snaplen;        /* aka "wirelen" */
		uint32_t network;        /* data link type */
} pcapfile_header_t; 

struct pcapfile_format_data_t {
	libtrace_io_t *file;
	pcapfile_header_t header;
};

struct pcapfile_format_data_out_t {
	libtrace_io_t *file;

};

static int pcapfile_init_input(libtrace_t *libtrace) {
	libtrace->format_data = malloc(sizeof(struct pcapfile_format_data_t));

	DATA(libtrace)->file=NULL;

	return 0;
}

static uint16_t swaps(libtrace_t *libtrace, uint16_t num)
{
	/* to deal with open_dead traces that might try and use this
	 * if we don't have any per trace data, assume host byte order
	 */
	if (!DATA(libtrace))
		return num;
	if (DATA(libtrace)->header.magic_number == 0xd4c3b2a1)
		return ((num<<8)&0xFF00)|((num>>8)&0x00FF);
	return num;
}

static uint32_t swapl(libtrace_t *libtrace, uint32_t num)
{
	/* to deal with open_dead traces that might try and use this
	 * if we don't have any per trace data, assume host byte order
	 */
	if (!DATA(libtrace))
		return num;
	if (DATA(libtrace)->header.magic_number == 0xd4c3b2a1)
		return 
			   ((num&0x000000FF)<<24)
			|| ((num&0x0000FF00)<<8)
			|| ((num&0x00FF0000)>>8)
			|| ((num&0xFF000000)>>24);
	return num;
}


static int pcapfile_start_input(libtrace_t *libtrace) 
{
	int err;

	if (!DATA(libtrace)->file) {
		DATA(libtrace)->file=trace_open_file(libtrace);

		if (!DATA(libtrace)->file)
			return -1;

		err=libtrace_io_read(DATA(libtrace)->file,
				&DATA(libtrace)->header,
				sizeof(DATA(libtrace)->header));

		if (err<1)
			return -1;
		
		if (swapl(libtrace,DATA(libtrace)->header.magic_number) != 0xa1b2c3d4) {
			trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"Not a pcap tracefile\n");
			return -1; /* Not a pcap file */
		}

		if (swaps(libtrace,DATA(libtrace)->header.version_major)!=2
			&& swaps(libtrace,DATA(libtrace)->header.version_minor)!=4) {
			trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"Unknown pcap tracefile version %d.%d\n",
					swaps(libtrace,
						DATA(libtrace)->header.version_major),
					swaps(libtrace,
						DATA(libtrace)->header.version_minor));
			return -1;
		}

	}

	return 0;
}

static int pcapfile_config_input(libtrace_t *libtrace,
		trace_option_t option,
		void *data)
{
	trace_set_err(libtrace,TRACE_ERR_UNKNOWN_OPTION,
			"Unknown option %i", option);
	return -1;
}

static int pcapfile_fin_input(libtrace_t *libtrace) 
{
	libtrace_io_close(DATA(libtrace)->file);
	free(libtrace->format_data);
	return 0; /* success */
}

static int pcapfile_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	int err;

	assert(libtrace->format_data);

	packet->type = pcap_dlt_to_rt(swapl(libtrace,
				DATA(libtrace)->header.network));

	if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
		packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
		packet->buf_control = TRACE_CTRL_PACKET;
	}

	err=libtrace_io_read(DATA(libtrace)->file,
			packet->buffer,
			sizeof(libtrace_pcapfile_pkt_hdr_t));

	if (err<0) {
		trace_set_err(libtrace,errno,"reading packet");
		return -1;
	}
	if (err==0) {
		/* EOF */
		return 0;
	}

	packet->header = packet->buffer;


	err=libtrace_io_read(DATA(libtrace)->file,
			(char*)packet->buffer+sizeof(libtrace_pcapfile_pkt_hdr_t),
			swapl(libtrace,((libtrace_pcapfile_pkt_hdr_t*)packet->buffer)->caplen)
			);

	
	if (err<0) {
		trace_set_err(libtrace,errno,"reading packet");
		return -1;
	}
	if (err==0) {
		return 0;
	}

	packet->payload = (char*)packet->buffer 
		+ sizeof(libtrace_pcapfile_pkt_hdr_t);
	
	return sizeof(libtrace_pcapfile_pkt_hdr_t)
		+swapl(libtrace,((libtrace_pcapfile_pkt_hdr_t*)packet->buffer)->caplen);
}

#if 0
static void pcapfile_write_packet(libtrace_out_t *out,
		const libtrace_packet_t *packet)
{
	struct pcapfile_pkt_hdr_t hdr;

	tv = trace_get_timeval(packet);
	hdr.ts_sec = tv.tv_sec;
	hdr.ts_usec = tv.tv_usec;
	hdr.caplen = trace_get_capture_length(packet);
	hdr.wirelen = trace_get_wire_length(packet);

	write(fd,&hdr,sizeof(hdr));
	write(fd,packet->payload,hdr.caplen);
	
}
#endif


static libtrace_linktype_t pcapfile_get_link_type(
		const libtrace_packet_t *packet) 
{
#if 0
	return pcap_dlt_to_libtrace(
			swapl(packet->trace,
				DATA(packet->trace)->header.network
			     )
			);
#endif
	return pcap_dlt_to_libtrace(rt_to_pcap_dlt(packet->type));
}

static libtrace_direction_t pcapfile_get_direction(const libtrace_packet_t *packet) 
{
	libtrace_direction_t direction  = -1;
	switch(pcapfile_get_link_type(packet)) {
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
			if (ntohs(sll->pkttype == 0)) {
				direction = TRACE_DIR_INCOMING;
			} else {
				direction = TRACE_DIR_OUTGOING;
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


static struct timeval pcapfile_get_timeval(
		const libtrace_packet_t *packet) 
{
	libtrace_pcapfile_pkt_hdr_t *hdr =
		(libtrace_pcapfile_pkt_hdr_t*)packet->header;
	struct timeval ts;
	ts.tv_sec = swapl(packet->trace,hdr->ts_sec);
	ts.tv_usec = swapl(packet->trace,hdr->ts_usec);
	return ts;
}


static int pcapfile_get_capture_length(const libtrace_packet_t *packet) {
	libtrace_pcapfile_pkt_hdr_t *pcapptr 
		= (libtrace_pcapfile_pkt_hdr_t *)packet->header;

	return swapl(packet->trace,pcapptr->caplen);
}

static int pcapfile_get_wire_length(const libtrace_packet_t *packet) {
	libtrace_pcapfile_pkt_hdr_t *pcapptr 
		= (libtrace_pcapfile_pkt_hdr_t *)packet->header;
	if (packet->type==pcap_dlt_to_rt(TRACE_DLT_EN10MB))
		/* Include the missing FCS */
		return swapl(packet->trace,pcapptr->wirelen)+4; 
	else
		return swapl(packet->trace,pcapptr->wirelen);
}

static int pcapfile_get_framing_length(const libtrace_packet_t *packet UNUSED) {
	return sizeof(libtrace_pcapfile_pkt_hdr_t);
}

static size_t pcapfile_set_capture_length(libtrace_packet_t *packet,size_t size) {
	libtrace_pcapfile_pkt_hdr_t *pcapptr = 0;
	assert(packet);
	if (size > trace_get_capture_length(packet)) {
		/* can't make a packet larger */
		return trace_get_capture_length(packet);
	}
	pcapptr = (libtrace_pcapfile_pkt_hdr_t *)packet->header;
	pcapptr->caplen = swapl(packet->trace,size);
	return trace_get_capture_length(packet);
}

static void pcapfile_help() {
	printf("pcapfile format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\tpcapfile:/path/to/file\n");
	printf("\tpcapfile:/path/to/file.gz\n");
	printf("\n");
	printf("\te.g.: pcapfile:/tmp/trace.pcap\n");
	printf("\n");
}

static struct libtrace_format_t pcapfile = {
	"pcapfile",
	"$Id$",
	TRACE_FORMAT_PCAPFILE,
	pcapfile_init_input,		/* init_input */
	pcapfile_config_input,		/* config_input */
	pcapfile_start_input,		/* start_input */
	NULL,				/* pause_input */
	NULL,			/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	pcapfile_fin_input,		/* fin_input */
	NULL,				/* fin_output */
	pcapfile_read_packet,		/* read_packet */
	NULL,				/* fin_packet */
	NULL,				/* write_packet */
	pcapfile_get_link_type,		/* get_link_type */
	pcapfile_get_direction,		/* get_direction */
	NULL,				/* set_direction */
	NULL,				/* get_erf_timestamp */
	pcapfile_get_timeval,		/* get_timeval */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	pcapfile_get_capture_length,	/* get_capture_length */
	pcapfile_get_wire_length,	/* get_wire_length */
	pcapfile_get_framing_length,	/* get_framing_length */
	pcapfile_set_capture_length,	/* set_capture_length */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	pcapfile_help,			/* help */
	NULL				/* next pointer */
};


void CONSTRUCTOR pcapfile_constructor() {
	register_format(&pcapfile);
}


