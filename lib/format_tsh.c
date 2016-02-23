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
#include "common.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* This format module deals with reading traces that are in the TSH format.
 *
 * We do not support writing TSH traces, because it's a pretty rubbish format.
 */

static struct libtrace_format_t tshformat;

typedef struct tsh_pkt_header_t {
	uint32_t seconds;
	uint32_t usecs;
} tsh_pkt_header_t;

static int tsh_get_framing_length(const libtrace_packet_t *packet UNUSED)
{
	return sizeof(tsh_pkt_header_t);
}


static int tsh_init_input(libtrace_t *libtrace) 
{
	libtrace->format_data = NULL; /* No format data */
	
	return 0; /* success */
}

static int tsh_start_input(libtrace_t *libtrace)
{
	if (libtrace->io)
		return 0; /* success */

	libtrace->io = trace_open_file(libtrace);

	if (!libtrace->io)
		return -1;

	return 0; /* success */
}

static int tsh_fin_input(libtrace_t *libtrace) {
	if (libtrace->io)
		wandio_destroy(libtrace->io);
	return 0;
}

static int tsh_prepare_packet(libtrace_t *libtrace, libtrace_packet_t *packet,
		void *buffer, libtrace_rt_types_t rt_type, uint32_t flags) {
	if (packet->buffer != buffer &&
                        packet->buf_control == TRACE_CTRL_PACKET) {
                free(packet->buffer);
        }

        if ((flags & TRACE_PREP_OWN_BUFFER) == TRACE_PREP_OWN_BUFFER) {
                packet->buf_control = TRACE_CTRL_PACKET;
        } else
                packet->buf_control = TRACE_CTRL_EXTERNAL;


        packet->buffer = buffer;
        packet->header = buffer;
	packet->type = rt_type;
	packet->payload = (char *)packet->buffer + sizeof(tsh_pkt_header_t);

	if (libtrace->format_data == NULL) {
		if (tsh_init_input(libtrace))
			return -1;
	}

	return 0;
}

static int tsh_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	int numbytes;
	void *buffer2 = packet->buffer;
	uint32_t flags = 0;

	if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
		packet->buffer = malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
		if (!packet->buffer) {
			trace_set_err(libtrace, errno, 
					"Cannot allocate memory");
			return -1;
		}
	}

	flags |= TRACE_PREP_OWN_BUFFER;
	packet->type = TRACE_RT_DATA_TSH;

	buffer2 = packet->buffer;

	/* Read the TSH header */
	if ((numbytes=wandio_read(libtrace->io,
					buffer2,
					(size_t)sizeof(tsh_pkt_header_t))) == -1) {
		trace_set_err(libtrace,errno,"read(%s)",
				libtrace->uridata);
		return -1;
	}
	/* EOF */
	if (numbytes == 0) {
		return 0;
	}

        if (numbytes < (int)sizeof(tsh_pkt_header_t)) {
                trace_set_err(libtrace, errno, "Incomplete TSH header");
                return -1;
        }

	buffer2 = (char*)buffer2 + numbytes;

	/* Read the IP header */
	if ((numbytes=wandio_read(libtrace->io,
				buffer2,
				(size_t)sizeof(libtrace_ip_t)+16))  /* 16 bytes of transport header */
			!= sizeof(libtrace_ip_t)+16) {
		trace_set_err(libtrace,errno,"read(%s)",
				libtrace->uridata);
		return -1;
	}

#if 0
	/* IP Options aren't captured in the trace, so leave room
	 * for them, and put the transport header where it "should" be
	 */
	buffer2 = (char*)buffer2 + ((libtrace_ip_t*)buffer2)->ip_hl*4;

	/* Read the transport header */
	if ((numbytes=wandio_read(libtrace->io,
				buffer2,
				16)) != 16) {
		trace_set_err(libtrace,errno,"read(%s)",
				libtrace->uridata);
		return -1;
	}
#endif
	
	if (tsh_prepare_packet(libtrace, packet, packet->buffer, packet->type, 
				flags)) {
		return -1;
	}


	return 80;
}

static libtrace_linktype_t tsh_get_link_type(const libtrace_packet_t *packet UNUSED) {
	return TRACE_TYPE_NONE;
}

static libtrace_direction_t tsh_get_direction(const libtrace_packet_t *packet) {
	return ntohl(((tsh_pkt_header_t*)(packet->header))->usecs & htonl(0xFF000000)) >> 24;
}

static struct timeval tsh_get_timeval(const libtrace_packet_t *packet)
{
	struct timeval tv;
	tv.tv_sec=ntohl(((tsh_pkt_header_t*)(packet->header))->seconds);
	tv.tv_usec=ntohl(((tsh_pkt_header_t*)(packet->header))->usecs & htonl(0x00FFFFFF));

	return tv;
}

static int tsh_get_capture_length(const libtrace_packet_t *packet UNUSED) {
	/* 16 bytes transport + 24 bytes IP, and we're missing the
	 * IP options, but we'll pretend we have them
	 */
#if 0
	return 16+((libtrace_ip_t*)packet->payload)->ip_hl*4;
#else
	return 16+sizeof(libtrace_ip_t);
#endif
}

static int tsh_get_wire_length(const libtrace_packet_t *packet) {
	return ntohs(((libtrace_ip_t*)packet->payload)->ip_len);
}

static void tsh_help(void) {
	printf("tsh format module: $Revision: 1611 $\n");
	printf("Supported input URIs:\n");
	printf("\ttsh:/path/to/file\t(uncompressed)\n");
	printf("\ttsh:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\ttsh:-\t(stdin, either compressed or not)\n");
	printf("\ttsh:/path/to/socket\n");
	printf("\n");
	printf("\te.g.: erf:/tmp/trace\n");
	printf("\n");
}

static struct libtrace_format_t tshformat = {
	"tsh",
	"$Id$",
	TRACE_FORMAT_TSH,
	NULL,				/* probe filename */
	NULL,				/* probe magic */
	tsh_init_input,			/* init_input */	
	NULL,				/* config_input */
	tsh_start_input,		/* start_input */
	NULL,				/* pause_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	tsh_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	tsh_read_packet,		/* read_packet */
	tsh_prepare_packet,		/* prepare_packet */
	NULL,				/* fin_packet */
	NULL,				/* write_packet */
	tsh_get_link_type,		/* get_link_type */
	tsh_get_direction,		/* get_direction */
	NULL,				/* set_direction */
	NULL,				/* get_erf_timestamp */
	tsh_get_timeval,		/* get_timeval */
	NULL,				/* get_timespec */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	tsh_get_capture_length,		/* get_capture_length */
	tsh_get_wire_length,		/* get_wire_length */
	tsh_get_framing_length,		/* get_framing_length */
	NULL,				/* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	NULL,				/* get_dropped_packets */
	NULL,				/* get_captured_packets */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	tsh_help,			/* help */
	NULL				/* next pointer */
};

/* the tsh header format is the same as tsh, except that the bits that will
 * always be "0" in the fr+ format are used for an "interface" identifier,
 * thus on tr+ traces, this will always be 0.  So, we use the exact same
 * decoder for both traces.
 */
static struct libtrace_format_t frplusformat = {
	"fr+",
	"$Id$",
	TRACE_FORMAT_TSH,
	NULL,				/* probe filename */
	NULL,				/* probe magic */
	tsh_init_input,			/* init_input */	
	NULL,				/* config_input */
	tsh_start_input,		/* start_input */
	NULL,				/* pause_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	tsh_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	tsh_read_packet,		/* read_packet */
	tsh_prepare_packet,		/* prepare_packet */
	NULL,				/* fin_packet */
	NULL,				/* write_packet */
	tsh_get_link_type,		/* get_link_type */
	tsh_get_direction,		/* get_direction */
	NULL,				/* set_direction */
	NULL,				/* get_erf_timestamp */
	tsh_get_timeval,		/* get_timeval */
	NULL,				/* get_timespec */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	tsh_get_capture_length,		/* get_capture_length */
	tsh_get_wire_length,		/* get_wire_length */
	tsh_get_framing_length,		/* get_framing_length */
	NULL,				/* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	NULL,				/* get_dropped_packets */
	NULL,				/* get_captured_packets */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	tsh_help,			/* help */
	NULL				/* next pointer */
};

void tsh_constructor(void) {
	register_format(&tshformat);
	register_format(&frplusformat);
}
