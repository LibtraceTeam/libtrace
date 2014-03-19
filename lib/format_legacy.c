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

#define _GNU_SOURCE

#include "config.h"
#include "common.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "wandio.h"

#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>

#ifdef WIN32
#  include <io.h>
#  include <share.h>
#endif

/* The format module deals with legacy DAG formats from older revisions of the
 * DAG hardware and software. Aside from a few minor differences, the legacy
 * formats are very similar so we can deal with them using the same callback
 * functions for the most part.
 *
 * These formats are intended for reading old ERF traces such as the earlier
 * Auckland traces.
 *
 * We definitely do not support writing using these formats - one should 
 * convert packets to regular ERF instead before writing.
 */

/* Several formats are covered in this source file:
 *
 * Legacy Ethernet:	as seen in Auckland VI
 * Legacy ATM:		as seen in Auckland II and IV
 * Legacy PoS:		as seen in Leipzig I and II
 * Legacy NZIX:		as seen in NZIX I
 */

/* Catch undefined O_LARGEFILE on *BSD etc */
#ifndef O_LARGEFILE
#  define O_LARGEFILE 0
#endif 

#ifndef UINT32_MAX
#  define UINT32_MAX 0xffffffff
#endif

#define DATA(x) ((struct legacy_format_data_t *)x->format_data)

/* Legacy NZIX timestamps are all relative to the start of the trace, so we
 * have to remember all sorts of stuff so that we can convert them into a
 * useful timestamp */

struct legacy_format_data_t {
	time_t starttime;	/* Time that the trace file was started */
	uint64_t ts_high;	/* The timestamp of the last packet */
	uint32_t ts_old; 	/* The timestamp of the last packet as 
				   reported in the NZIX header */
};

static void legacy_init_format_data(libtrace_t *libtrace) {
	libtrace->format_data = malloc(sizeof(struct legacy_format_data_t));
	
	DATA(libtrace)->ts_high = 0;
	DATA(libtrace)->ts_old = 0;
	DATA(libtrace)->starttime = 0;
}

static int legacyeth_get_framing_length(const libtrace_packet_t *packet UNUSED) 
{
	return sizeof(legacy_ether_t);
}

static int legacypos_get_framing_length(const libtrace_packet_t *packet UNUSED) 
{
	return sizeof(legacy_pos_t);
}

static int legacyatm_get_framing_length(const libtrace_packet_t *packet UNUSED) 
{
	return sizeof(legacy_cell_t);
}

static int legacynzix_get_framing_length(const libtrace_packet_t *packet UNUSED)
{
	return sizeof(legacy_nzix_t);
}

static int erf_init_input(libtrace_t *libtrace) 
{
	legacy_init_format_data(libtrace);

	return 0;
}

/* Takes a trace file name and determines the time that the capture began.
 *
 * NZIX only features relative timestamps so the trace file name is the only
 * indication we have of where the relative timestamping begins from
 */
static time_t trtime(char *s) {
	/* XXX: this function may not be particularly portable to
	 * other platforms, e.g. *BSDs, Windows */
	struct tm tm;
	time_t ret;

	if(sscanf(s, "%4u%2u%2u-%2u%2u%2u", &tm.tm_year, &tm.tm_mon,
				&tm.tm_mday, &tm.tm_hour, &tm.tm_min,
				&tm.tm_sec) != 6) {
		return (time_t)0;
	}
	tm.tm_year = tm.tm_year - 1900;
	tm.tm_mon --;
	tm.tm_wday = 0; /* ignored */
	tm.tm_yday = 0; /* ignored */
	tm.tm_isdst = -1; /* forces check for summer time */
	
	/*
	if (getenv("TZ") == NULL) {
		fprintf(stderr, "Failed to get the current TZ");
		return (time_t)0;
	}
	*/
	if (putenv("TZ=Pacific/Auckland")) {
		perror("putenv");
		return (time_t)0;
	}
	tzset();
	ret = mktime(&tm);

	return ret;
}
	

static int legacynzix_init_input(libtrace_t *libtrace) {

	int retval;
	char *filename = libtrace->uridata;
	regex_t reg;
	regmatch_t match;


	legacy_init_format_data(libtrace);	
	
	/* Check that the filename appears to contain a suitable timestamp.
	 * Without it, we have no way of determining the actual timestamps
	 * for each packet */
	if((retval = regcomp(&reg, "[0-9]{8}-[0-9]{6}", REG_EXTENDED)) != 0) {
		trace_set_err(libtrace, errno, "Failed to compile regex");
		return -1;
	}
	if ((retval = regexec(&reg, filename, 1, &match, 0)) !=0) {
		trace_set_err(libtrace, errno, "Failed to exec regex");
		return -1;
	}
	DATA(libtrace)->starttime = trtime(&filename[match.rm_so]);
	return 0;
}

/* All of the formats can be started in exactly the same way */
static int erf_start_input(libtrace_t *libtrace)
{
	if (libtrace->io)
		return 0; /* Already open */

	libtrace->io = trace_open_file(libtrace);

	if (libtrace->io)
		return 0;

	return -1;
}

static int erf_fin_input(libtrace_t *libtrace) {
	wandio_destroy(libtrace->io);
	free(libtrace->format_data);
	return 0;
}

static int legacy_prepare_packet(libtrace_t *libtrace, 
		libtrace_packet_t *packet, void *buffer, 
		libtrace_rt_types_t rt_type, uint32_t flags) {

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
	packet->payload = (void*)((char*)packet->buffer + 
		libtrace->format->get_framing_length(packet));


	if (libtrace->format_data == NULL) {
		legacy_init_format_data(libtrace);
	}
	return 0;
}

static int legacy_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	int numbytes;
	void *buffer;
	uint32_t flags = 0;
	
	if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
		packet->buffer=malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
	}
	flags |= TRACE_PREP_OWN_BUFFER;
	buffer = packet->buffer;

	switch(libtrace->format->type) {
		case TRACE_FORMAT_LEGACY_ATM:
			packet->type = TRACE_RT_DATA_LEGACY_ATM;
			break;
		case TRACE_FORMAT_LEGACY_POS:
			packet->type = TRACE_RT_DATA_LEGACY_POS;
			break;
		case TRACE_FORMAT_LEGACY_ETH:
			packet->type = TRACE_RT_DATA_LEGACY_ETH;
			break;
		default:
			assert(0);
	}

	/* This is going to block until we either get an entire record
	 * or we reach the end of the file */
	while (1) {
	
		if ((numbytes=wandio_read(libtrace->io,
						buffer,
						(size_t)64)) != 64) {
			if (numbytes < 0) {
				trace_set_err(libtrace,errno,"read(%s)",libtrace->uridata);
			} else if (numbytes > 0) {
				
				continue;
			}
			return numbytes;
		}
		break;
	}
	
	if (legacy_prepare_packet(libtrace, packet, packet->buffer, 
				packet->type, flags)) {
		return -1;
	}
	
	return 64;
	
}

static int legacynzix_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	/* Firstly, I apologize for all the constants being thrown around in
	 * this function, but it does befit the hackish origins of the
	 * NZIX format that I use them. Anyone who wants to clean them up is
	 * welcome to do so */
	int numbytes;
	void *buffer;
	char *data_ptr;
	uint32_t flags = 0;
	
	if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
		packet->buffer=malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
	}
	flags |= TRACE_PREP_OWN_BUFFER;
	
	buffer = packet->buffer;
	packet->type = TRACE_RT_DATA_LEGACY_NZIX;
	
	while (1) {
		if ((numbytes = wandio_read(libtrace->io, buffer,
						(size_t)68)) != 68) {
			if (numbytes < 0) {
				trace_set_err(libtrace,errno,"read(%s)",libtrace->uridata);
			} else if (numbytes > 0)
				continue;
			return numbytes;
		} 
		/* Packets with a zero length are GPS timestamp packets
		 * but they aren't inserted at the right time to be
		 * useful - instead we'll ignore them unless we can think
		 * of a compelling reason to do otherwise */
		if (((legacy_nzix_t *)buffer)->len == 0)
			continue;
		
		break;
	}

	/* Lets move the padding so that it's in the framing header */
	data_ptr = ((char *)buffer) + 12;
	memmove(data_ptr + 2, data_ptr, 26);

	if (legacy_prepare_packet(libtrace, packet, packet->buffer, 
				packet->type, flags)) {
		return -1;
	}
	return 68;
}
		

static libtrace_linktype_t legacypos_get_link_type(
		const libtrace_packet_t *packet) {
	/* POS can be PPP over HDLC (DLT_PPP_SERIAL), or it can be
 	 * just straight PPP.  Sigh.
 	 *
 	 * Ref: RFC 1549
 	 * 	- Perry Lorier (2008-11-04)
 	 */
	
	/* It can also be CHDLC, which is different again */
	
	/* This check matchs PPP over HDLC, a la RFC 1662 */
	if (((char *)packet->payload)[0] == '\xFF'
		&& ((char*)packet->payload)[1] == '\x03')
		return TRACE_TYPE_POS;
	
	/* This check matches unicast CHDLC */
	else if (((char *)packet->payload)[0] == '\x0F' &&
		((char*)packet->payload)[1] == '\x00')
		return TRACE_TYPE_HDLC_POS;
	
	/* This check matches broadcast CHDLC */
	else if (((char *)packet->payload)[0] == '\x8F' &&
		((char*)packet->payload)[1] == '\x00')
		return TRACE_TYPE_HDLC_POS;

	/* Otherwise just assume raw PPP (?) */
	else 
		return TRACE_TYPE_PPP;
}

static libtrace_linktype_t legacyatm_get_link_type(
		const libtrace_packet_t *packet UNUSED) {
	return TRACE_TYPE_ATM;
}

static libtrace_linktype_t legacyeth_get_link_type(const libtrace_packet_t *packet UNUSED) {
	return TRACE_TYPE_ETH;
}

static libtrace_linktype_t legacynzix_get_link_type(const libtrace_packet_t *packet UNUSED) {
	return TRACE_TYPE_ETH;
}

static int legacy_get_capture_length(const libtrace_packet_t *packet UNUSED) {
	return 64;
}

static int legacynzix_get_capture_length(const libtrace_packet_t *packet UNUSED)
{
	return 54;
}

static int legacypos_get_wire_length(const libtrace_packet_t *packet) {
	legacy_pos_t *lpos = (legacy_pos_t *)packet->header;
	assert(ntohl(lpos->wlen)>0);
	return ntohl(lpos->wlen);
}

static int legacyatm_get_wire_length(const libtrace_packet_t *packet UNUSED) {
	return 53;
}

static int legacyeth_get_wire_length(const libtrace_packet_t *packet) {
	legacy_ether_t *leth = (legacy_ether_t *)packet->header; 
	return leth->wlen+4; /* +4 for FCS, wirelen is in little endian sigh. */
}

static int legacynzix_get_wire_length(const libtrace_packet_t *packet) {
	legacy_nzix_t *lnzix = (legacy_nzix_t *)packet->header;
	return lnzix->len;
}

static uint64_t legacy_get_erf_timestamp(const libtrace_packet_t *packet)
{
	legacy_ether_t *legacy = (legacy_ether_t*)packet->header;
	return bswap_le_to_host64(legacy->ts);
}  

static uint32_t ts_cmp(uint32_t ts_a, uint32_t ts_b) {
	
	/* each ts is actually a 30 bit value */
	ts_a <<= 2;
	ts_b <<= 2;


	if (ts_a > ts_b) 
		return (ts_a - ts_b);
	else
		return (ts_b - ts_a);
	
}

static struct timeval legacynzix_get_timeval(const libtrace_packet_t *packet) {
	uint64_t new_ts = DATA(packet->trace)->ts_high;
	uint32_t old_ts = DATA(packet->trace)->ts_old;
	struct timeval tv;
	uint32_t hdr_ts;

	legacy_nzix_t *legacy = (legacy_nzix_t *)packet->header;
		
	hdr_ts = legacy->ts;

	/* Seems we only need 30 bits to represent our timestamp */
	hdr_ts >>=2;
	
	/* Try a sequence number wrap-around comparison */
	if (ts_cmp(hdr_ts, old_ts) > (UINT32_MAX / 2) )
		new_ts += (1LL << 30); /* Wraparound */
	new_ts &= ~((1LL << 30) -1);	/* Mask lower 30 bits */
	new_ts += hdr_ts;		/* Packet ts is the new 30 bits */
	DATA(packet->trace)->ts_old = hdr_ts;

	tv.tv_sec = DATA(packet->trace)->starttime + (new_ts / (1000 * 1000));
	tv.tv_usec = new_ts % (1000 * 1000);
	DATA(packet->trace)->ts_high = new_ts;


	/*dts = tv.tv_sec + (double)tv.tv_usec / 1000 / 1000; */
	return tv;
	
}	

static void legacypos_help(void) {
	printf("legacypos format module: $Revision: 1753 $\n");
	printf("Supported input URIs:\n");
	printf("\tlegacypos:/path/to/file\t(uncompressed)\n");
	printf("\tlegacypos:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\tlegacypos:-\t(stdin, either compressed or not)\n");
	printf("\n");
	printf("\te.g.: legacypos:/tmp/trace.gz\n");
	printf("\n");
}

static void legacyatm_help(void) {
	printf("legacyatm format module: $Revision: 1753 $\n");
	printf("Supported input URIs:\n");
	printf("\tlegacyatm:/path/to/file\t(uncompressed)\n");
	printf("\tlegacyatm:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\tlegacyatm:-\t(stdin, either compressed or not)\n");
	printf("\n");
	printf("\te.g.: legacyatm:/tmp/trace.gz\n");
	printf("\n");
}

static void legacyeth_help(void) {
	printf("legacyeth format module: $Revision: 1753 $\n");
	printf("Supported input URIs:\n");
	printf("\tlegacyeth:/path/to/file\t(uncompressed)\n");
	printf("\tlegacyeth:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\tlegacyeth:-\t(stdin, either compressed or not)\n");
	printf("\n");
	printf("\te.g.: legacyeth:/tmp/trace.gz\n");
	printf("\n");
}

static void legacynzix_help(void) {
	printf("legacynzix format module: $Revision: 1753 $\n");
	printf("Supported input URIs:\n");
	printf("\tlegacynzix:/path/to/file\t(uncompressed)\n");
	printf("\tlegacynzix:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\tlegacynzix:-\t(stdin, either compressed or not)\n");
	printf("\n");
	printf("\te.g.: legacynzix:/tmp/trace.gz\n");
	printf("\n");
}

static struct libtrace_format_t legacyatm = {
	"legacyatm",
	"$Id$",
	TRACE_FORMAT_LEGACY_ATM,
	NULL,				/* probe filename */
	NULL,				/* probe magic */
	erf_init_input,			/* init_input */	
	NULL,				/* config_input */
	erf_start_input,		/* start_input */
	NULL,				/* pause_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	erf_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	legacy_read_packet,		/* read_packet */
	legacy_prepare_packet,		/* prepare_packet */
	NULL,				/* fin_packet */
	NULL,				/* write_packet */
	legacyatm_get_link_type,	/* get_link_type */
	NULL,				/* get_direction */
	NULL,				/* set_direction */
	legacy_get_erf_timestamp,	/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_timespec */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	legacy_get_capture_length,	/* get_capture_length */
	legacyatm_get_wire_length,	/* get_wire_length */
	legacyatm_get_framing_length,	/* get_framing_length */
	NULL,				/* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	NULL,				/* get_dropped_packets */
	NULL,				/* get_captured_packets */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	legacyatm_help,			/* help */
	NULL				/* next pointer */
};

static struct libtrace_format_t legacyeth = {
	"legacyeth",
	"$Id$",
	TRACE_FORMAT_LEGACY_ETH,
	NULL,				/* probe filename */
	NULL,				/* probe magic */
	erf_init_input,			/* init_input */	
	NULL,				/* config_input */
	erf_start_input,		/* start_input */
	NULL,				/* pause_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	erf_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	legacy_read_packet,		/* read_packet */
	legacy_prepare_packet,		/* prepare_packet */
	NULL,				/* fin_packet */
	NULL,				/* write_packet */
	legacyeth_get_link_type,	/* get_link_type */
	NULL,				/* get_direction */
	NULL,				/* set_direction */
	legacy_get_erf_timestamp,	/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_timespec */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	legacy_get_capture_length,	/* get_capture_length */
	legacyeth_get_wire_length,	/* get_wire_length */
	legacyeth_get_framing_length,	/* get_framing_length */
	NULL,				/* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	NULL,				/* get_dropped_packets */
	NULL,				/* get_captured_packets */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	legacyeth_help,			/* help */
	NULL				/* next pointer */
};

static struct libtrace_format_t legacypos = {
	"legacypos",
	"$Id$",
	TRACE_FORMAT_LEGACY_POS,
	NULL,				/* probe filename */
	NULL,				/* probe magic */
	erf_init_input,			/* init_input */	
	NULL,				/* config_input */
	erf_start_input,		/* start_input */
	NULL,				/* pause_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	erf_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	legacy_read_packet,		/* read_packet */
	legacy_prepare_packet,		/* prepare_packet */
	NULL,				/* fin_packet */
	NULL,				/* write_packet */
	legacypos_get_link_type,	/* get_link_type */
	NULL,				/* get_direction */
	NULL,				/* set_direction */
	legacy_get_erf_timestamp,	/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_timespec */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	legacy_get_capture_length,	/* get_capture_length */
	legacypos_get_wire_length,	/* get_wire_length */
	legacypos_get_framing_length,	/* get_framing_length */
	NULL,				/* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	NULL,				/* get_dropped_packets */
	NULL,				/* get_captured_packets */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	legacypos_help,			/* help */
	NULL,				/* next pointer */
};

static struct libtrace_format_t legacynzix = {
	"legacynzix",
	"$Id$",
	TRACE_FORMAT_LEGACY_NZIX,
	NULL,				/* probe filename */
	NULL,				/* probe magic */
	legacynzix_init_input,		/* init_input */	
	NULL,				/* config_input */
	erf_start_input,		/* start_input */
	NULL,				/* pause_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	erf_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	legacynzix_read_packet,		/* read_packet */
	legacy_prepare_packet,		/* prepare_packet */
	NULL,				/* fin_packet */
	NULL,				/* write_packet */
	legacynzix_get_link_type,	/* get_link_type */
	NULL,				/* get_direction */
	NULL,				/* set_direction */
	NULL,				/* get_erf_timestamp */
	legacynzix_get_timeval,		/* get_timeval */
	NULL,				/* get_timespec */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	legacynzix_get_capture_length,	/* get_capture_length */
	legacynzix_get_wire_length,	/* get_wire_length */
	legacynzix_get_framing_length,	/* get_framing_length */
	NULL,				/* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	NULL,				/* get_dropped_packets */
	NULL,				/* get_captured_packets */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	legacynzix_help,		/* help */
	NULL,				/* next pointer */
};
	
void legacy_constructor(void) {
	register_format(&legacypos);
	register_format(&legacyeth);
	register_format(&legacyatm);
	register_format(&legacynzix);
}
