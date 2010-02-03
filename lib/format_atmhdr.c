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

/* This particular format covers the ATM cell header capture format used to
 * take the Auckland VII trace set.
 *
 * Each capture record contains only a timestamp and the first four bytes of 
 * the ATM header - nothing else. 
 *
 * As a result, there isn't a lot you can actually do with these traces!
 *
 * Libtrace does not support writing using this format, because it is so
 * useless :)
 */

/* Returns the size of the ATM cell framing header */
static int atmhdr_get_framing_length(const libtrace_packet_t *packet UNUSED)
{
	return sizeof(atmhdr_t);
}

/* Initialise an input trace to read an ATM cell header capture */
static int atmhdr_init_input(libtrace_t *libtrace) {
	libtrace->format_data = NULL; /* No format data needed */
	return 0;
}

/* Start an ATM cell header input trace */
static int atmhdr_start_input(libtrace_t *libtrace)
{
	if (libtrace->io) /* Already open? */
		return 0;
	libtrace->io = trace_open_file(libtrace);
	if (libtrace->io)
		return 0;
	return -1;
}

/* Close an ATM cell header input trace */
static int atmhdr_fin_input(libtrace_t *libtrace)
{
	wandio_destroy(libtrace->io);
	return 0;
}


/* Converts a buffer containing a recently read ATM cell header record into
 * a libtrace packet */
static int atmhdr_prepare_packet(libtrace_t *libtrace, 
		libtrace_packet_t *packet, void *buffer, 
		libtrace_rt_types_t rt_type, uint32_t flags) {

	/* If the packet previously owned a buffer that was not the buffer
	 * containing the new packet data, we need to free the old one to 
	 * avoid leaking memory */
	if (packet->buffer != buffer &&
                        packet->buf_control == TRACE_CTRL_PACKET) {
                free(packet->buffer);
        }

	/* Set the buffer owner appropriately */
        if ((flags & TRACE_PREP_OWN_BUFFER) == TRACE_PREP_OWN_BUFFER) {
                packet->buf_control = TRACE_CTRL_PACKET;
        } else
                packet->buf_control = TRACE_CTRL_EXTERNAL;

	/* Update the packet pointers appropriately */
	packet->buffer = buffer;
	packet->header = buffer;
	packet->payload = (void*)((char*)packet->buffer + 
			libtrace->format->get_framing_length(packet));

	/* Set the packet type */
	packet->type = rt_type;

	return 0;
}

/* Reads the next ATM cell header record from the given trace and writes it
 * into a libtrace packet */
static int atmhdr_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	int numbytes;
	void *buffer;
	uint32_t flags = 0;
	
	/* Make sure we have a buffer available to read the next record into */
	if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
		packet->buffer=malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
	}
	buffer = packet->buffer;
	flags |= TRACE_PREP_OWN_BUFFER;
	
	packet->type = TRACE_RT_DATA_ATMHDR;

	/* The records are a fixed size so we can read the entire record in
	 * one go */
	if ((numbytes=wandio_read(libtrace->io, buffer, (size_t)12)) != 12)
	{
		if (numbytes != 0) {
			trace_set_err(libtrace,errno,"read(%s)",libtrace->uridata);
		}
		return numbytes;
	}

	/* Update all our packet pointers appropriately */
	if (atmhdr_prepare_packet(libtrace, packet, buffer, 
				TRACE_RT_DATA_ATMHDR, flags)) {
		return -1;
	}
				
	
	return 12;
}

/* Get the link type for an ATM cell header record */
static libtrace_linktype_t atmhdr_get_link_type(const libtrace_packet_t *packet UNUSED) {
	/* Unsurprisingly, we're always going to be an ATM header */
	return TRACE_TYPE_ATM;
}

/* Get the capture length for an ATM cell header record */
static int atmhdr_get_capture_length(const libtrace_packet_t *packet UNUSED) {
	/* There is always 4 bytes of ATM header retained by this format */
	return 4;
}

/* Get the wire length for an ATM cell header record */
static int atmhdr_get_wire_length(const libtrace_packet_t *packet UNUSED) {
	/* ATM packets are 53 byte fixed length records */
	return 53;
}

/* Returns the timestamp for an ATM cell header record in the ERF timestamp
 * format */
static uint64_t atmhdr_get_erf_timestamp(const libtrace_packet_t *packet) {
	uint64_t ts;
	atmhdr_t *atm = (atmhdr_t *)packet->header;
	
	/* Basically, the capture format header is an ERF timestamp except
	 * the two 32-bit segments are reversed */
	ts = (uint64_t)atm->ts_fraction + ((uint64_t)atm->ts_sec << 32);

	return ts;
}

static struct libtrace_format_t atmhdr = {
	"atmhdr",
	"$Id$",
	TRACE_FORMAT_ATMHDR,
	NULL,				/* probe filename */
	NULL,				/* probe magic */
        atmhdr_init_input,              /* init_input */
        NULL,                           /* config_input */
        atmhdr_start_input,             /* start_input */
        NULL,                           /* pause_input */
        NULL,                           /* init_output */
        NULL,                           /* config_output */
        NULL,                           /* start_output */
        atmhdr_fin_input,               /* fin_input */
        NULL,                           /* fin_output */
        atmhdr_read_packet,             /* read_packet */
        atmhdr_prepare_packet,		/* prepare_packet */
	NULL,                           /* fin_packet */
        NULL,                           /* write_packet */
        atmhdr_get_link_type,        	/* get_link_type */
        NULL,                           /* get_direction */
        NULL,                           /* set_direction */
        atmhdr_get_erf_timestamp,       /* get_erf_timestamp */
        NULL,                           /* get_timeval */
	NULL,				/* get_timespec */
        NULL,                           /* get_seconds */
        NULL,                           /* seek_erf */
        NULL,                           /* seek_timeval */
        NULL,                           /* seek_seconds */
        atmhdr_get_capture_length,      /* get_capture_length */
        atmhdr_get_wire_length,      	/* get_wire_length */
        atmhdr_get_framing_length,   	/* get_framing_length */
        NULL,                           /* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	NULL,				/* get_dropped_packets */
	NULL,				/* get_captured_packets */
        NULL,                           /* get_fd */
        trace_event_trace,              /* trace_event */
        NULL,                 		/* help */
        NULL                            /* next pointer */
};
	

void atmhdr_constructor(void) {
	register_format(&atmhdr);
}
