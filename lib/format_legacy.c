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
#define _GNU_SOURCE

#include "config.h"
#include "common.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "parse_cmd.h"

#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#else
#  error "Can't find inttypes.h - this needs to be fixed"
#endif 

#ifdef HAVE_STDDEF_H
#  include <stddef.h>
#else
# error "Can't find stddef.h - do you define ptrdiff_t elsewhere?"
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#define COLLECTOR_PORT 3435

/* Catch undefined O_LARGEFILE on *BSD etc */
#ifndef O_LARGEFILE
#  define O_LARGEFILE 0
#endif 

static struct libtrace_format_t legacypos;
static struct libtrace_format_t legacyeth;
static struct libtrace_format_t legacyatm;

#define DATA(x) ((struct legacy_format_data_t *)x->format_data)

#define INPUT DATA(libtrace)->input
#if HAVE_DAG
#define DAG DATA(libtrace)->dag
#endif

struct legacy_format_data_t {
	union {
                int fd;
#if HAVE_ZLIB
                gzFile *file;
#else	
		/*FILE  *file; */
		int file;
#endif
        } input;
};

static int legacyeth_get_framing_length(const struct libtrace_packet_t *packet UNUSED) 
{
	return sizeof(legacy_ether_t);
}

static int legacypos_get_framing_length(const struct libtrace_packet_t *packet UNUSED) 
{
	return sizeof(legacy_pos_t);
}

static int legacyatm_get_framing_length(const struct libtrace_packet_t *packet UNUSED) 
{
	return sizeof(legacy_cell_t);
}

static int erf_init_input(struct libtrace_t *libtrace) 
{
	libtrace->format_data = malloc(sizeof(struct legacy_format_data_t));

	return 0;
}

static int erf_start_input(libtrace_t *libtrace)
{
	DATA(libtrace)->input.file = trace_open_file(libtrace);

	if (DATA(libtrace)->input.file)
		return 0;

	return -1;
}

static int erf_fin_input(struct libtrace_t *libtrace) {
	LIBTRACE_CLOSE(INPUT.file);
	free(libtrace->format_data);
	return 0;
}

static int legacy_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes;
	void *buffer;

	if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
		packet->buf_control = TRACE_CTRL_PACKET;
		packet->buffer=malloc(LIBTRACE_PACKET_BUFSIZE);
	}
	buffer = packet->buffer;

	switch(libtrace->format->type) {
		case TRACE_FORMAT_LEGACY_ATM:
			packet->type = RT_DATA_LEGACY_ATM;
			break;
		case TRACE_FORMAT_LEGACY_POS:
			packet->type = RT_DATA_LEGACY_POS;
			break;
		case TRACE_FORMAT_LEGACY_ETH:
			packet->type = RT_DATA_LEGACY_ETH;
			break;
		default:
			assert(0);
	}
	
	if ((numbytes=LIBTRACE_READ(INPUT.file,
					buffer,
					64)) == -1) {
		trace_set_err(libtrace,errno,"read(%s)",libtrace->uridata);
		return -1;
	}
	
	packet->header = packet->buffer;
	packet->payload = (void*)((char*)packet->buffer + 
		libtrace->format->get_framing_length(packet));
	
	return 64;
	
}

static libtrace_linktype_t legacypos_get_link_type(const struct libtrace_packet_t *packet UNUSED) {
	return TRACE_TYPE_LEGACY_POS;
}

static libtrace_linktype_t legacyatm_get_link_type(const struct libtrace_packet_t *packet UNUSED) {
	return TRACE_TYPE_LEGACY_ATM;
}

static libtrace_linktype_t legacyeth_get_link_type(const struct libtrace_packet_t *packet UNUSED) {
	return TRACE_TYPE_LEGACY_ETH;
}

static int legacy_get_capture_length(const struct libtrace_packet_t *packet __attribute__((unused))) {
	return 64;
}

static int legacypos_get_wire_length(const struct libtrace_packet_t *packet) {
	legacy_pos_t *lpos = (legacy_pos_t *)packet->header;
	return ntohs(lpos->wlen);
}

static int legacyatm_get_wire_length(const struct libtrace_packet_t *packet UNUSED) {
	return 53;
}

static int legacyeth_get_wire_length(const struct libtrace_packet_t *packet) {
	legacy_ether_t *leth = (legacy_ether_t *)packet->header;
	return ntohs(leth->wlen);
}

static uint64_t legacy_get_erf_timestamp(const struct libtrace_packet_t *packet)
{
	legacy_ether_t *legacy = (legacy_ether_t*)packet->header;
	return legacy->ts;
}  

static void legacypos_help() {
	printf("legacypos format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\tlegacypos:/path/to/file\t(uncompressed)\n");
	printf("\tlegacypos:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\tlegacypos:-\t(stdin, either compressed or not)\n");
	printf("\n");
	printf("\te.g.: legacypos:/tmp/trace.gz\n");
	printf("\n");
}

static void legacyatm_help() {
	printf("legacyatm format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\tlegacyatm:/path/to/file\t(uncompressed)\n");
	printf("\tlegacyatm:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\tlegacyatm:-\t(stdin, either compressed or not)\n");
	printf("\n");
	printf("\te.g.: legacyatm:/tmp/trace.gz\n");
	printf("\n");
}

static void legacyeth_help() {
	printf("legacyeth format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\tlegacyeth:/path/to/file\t(uncompressed)\n");
	printf("\tlegacyeth:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\tlegacyeth:-\t(stdin, either compressed or not)\n");
	printf("\n");
	printf("\te.g.: legacyeth:/tmp/trace.gz\n");
	printf("\n");
}

static struct libtrace_format_t legacyatm = {
	"legacyatm",
	"$Id$",
	TRACE_FORMAT_LEGACY_ATM,
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
	NULL,				/* fin_packet */
	NULL,				/* write_packet */
	legacyatm_get_link_type,	/* get_link_type */
	NULL,				/* get_direction */
	NULL,				/* set_direction */
	legacy_get_erf_timestamp,	/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	legacy_get_capture_length,	/* get_capture_length */
	legacyatm_get_wire_length,	/* get_wire_length */
	legacyatm_get_framing_length,	/* get_framing_length */
	NULL,				/* set_capture_length */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	legacyatm_help,			/* help */
	NULL				/* next pointer */
};

static struct libtrace_format_t legacyeth = {
	"legacyeth",
	"$Id$",
	TRACE_FORMAT_LEGACY_ETH,
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
	NULL,				/* fin_packet */
	NULL,				/* write_packet */
	legacyeth_get_link_type,	/* get_link_type */
	NULL,				/* get_direction */
	NULL,				/* set_direction */
	legacy_get_erf_timestamp,	/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	legacy_get_capture_length,	/* get_capture_length */
	legacyeth_get_wire_length,	/* get_wire_length */
	legacyeth_get_framing_length,	/* get_framing_length */
	NULL,				/* set_capture_length */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	legacyeth_help,			/* help */
	NULL				/* next pointer */
};

static struct libtrace_format_t legacypos = {
	"legacypos",
	"$Id$",
	TRACE_FORMAT_LEGACY_POS,
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
	NULL,				/* fin_packet */
	NULL,				/* write_packet */
	legacypos_get_link_type,	/* get_link_type */
	NULL,				/* get_direction */
	NULL,				/* set_direction */
	legacy_get_erf_timestamp,	/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	legacy_get_capture_length,	/* get_capture_length */
	legacypos_get_wire_length,	/* get_wire_length */
	legacypos_get_framing_length,	/* get_framing_length */
	NULL,				/* set_capture_length */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	legacypos_help,			/* help */
	NULL,				/* next pointer */
};

	
static void __attribute__((constructor)) legacy_constructor() {
	register_format(&legacypos);
	register_format(&legacyeth);
	register_format(&legacyatm);
}
