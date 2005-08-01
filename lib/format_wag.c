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

#include "libtrace.h"
#include "format.h"
#include "wag.h"

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
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif
static int wag_init_input(struct libtrace_t *libtrace) {
	struct stat buf;
	struct hostent *he;
	struct sockaddr_in remote;
	struct sockaddr_un unix_sock;
	if (!strncmp(libtrace->conn_info.path,"-",1)) {
		// STDIN
#if HAVE_ZLIB
		libtrace->input.file = gzdopen(STDIN, "r");
#else	
		libtrace->input.file = stdin;
#endif

	} else {
		if (stat(libtrace->conn_info.path,&buf) == -1 ) {
			perror("stat");
			return 0;
		}
		if (S_ISSOCK(buf.st_mode)) {
			// SOCKET
			if ((libtrace->input.fd = socket(
					AF_UNIX, SOCK_STREAM, 0)) == -1) {
				perror("socket");
				return 0;
			}
			unix_sock.sun_family = AF_UNIX;
			bzero(unix_sock.sun_path,108);
			snprintf(unix_sock.sun_path,
					108,"%s"
					,libtrace->conn_info.path);

			if (connect(libtrace->input.fd, 
					(struct sockaddr *)&unix_sock,
					sizeof(struct sockaddr)) == -1) {
				perror("connect (unix)");
				return 0;
			}
		} else { 
			// TRACE
#if HAVE_ZLIB
			// using gzdopen means we can set O_LARGEFILE
			// ourselves. However, this way is messy and 
			// we lose any error checking on "open"
			libtrace->input.file = 
				gzdopen(open(
					libtrace->conn_info.path,
					O_LARGEFILE), "r");
#else
			libtrace->input.file = 
				fdopen(open(
					libtrace->conn_info.path,
					O_LARGEFILE), "r");
#endif

		}
	}
}

static int wag_fin_input(struct libtrace_t *libtrace) {
#if HAVE_ZLIB
	gzclose(libtrace->input.file);
#else	
	fclose(libtrace->input.file);	
#endif
}

static int wag_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes;
	int size;
	char buf[RP_BUFSIZE];
	int read_required = 0;
	struct wag_frame_hdr *waghdr = 0;

	void *buffer = 0;

	packet->trace = libtrace;
	buffer = packet->buffer;
	

	do {
		if (fifo_out_available(libtrace->fifo) == 0 || read_required) {
			if ((numbytes = wag_read(libtrace,buf,RP_BUFSIZE)) <= 0) {
				return numbytes;
			}
			assert(libtrace->fifo);
			fifo_write(libtrace->fifo,buf,numbytes);
			read_required = 0;
		}
		// read in wag_frame_hdr
		if ((numbytes = fifo_out_read(libtrace->fifo, 
						buffer,
						sizeof(struct wag_frame_hdr)))
				== 0 ) {
			fifo_out_reset(libtrace->fifo);
			read_required = 1;
			continue;
		}
		size = ntohs(((struct wag_frame_hdr *)buffer)->size);

		// read in full packet
		if((numbytes = fifo_out_reaD(libtrace->fifo,buffer,size)) == 0) {
			fifo_out_reset(libtrace->fifo);
			read_required = 1;
			continue;
		}

		// have the whole packet
		fifo_out_update(libtrace->fifo,size);
		fifo_ack_update(libtrace->fifo,size);

		packet->size = numbytes;
		return numbytes;
	} while(1);
}

static void *wag_get_link(const struct libtrace_packet_t *packet) {
	struct wag_data_frame *wagptr = (struct wag_data_frame *)packet->buffer;
	void *payload = wagptr->data;
	return (void*)payload;
}

static libtrace_linktype_t wag_get_link_type(const struct libtrace_packet_t *packet) {
	return TRACE_TYPE_80211;
}

static int8_t wag_get_direction(const struct libtrace_packet_t *packet) {
	struct wag_data_frame *wagptr = (struct wag_data_frame *)packet->buffer;
	if (wagptr->hdr.type == 0) {
		return wagptr->hdr.subtype;
	}
	return -1;
}

static uint64_t wag_get_erf_timestamp(const struct libtrace_packet_t *packet) {
	struct wag_data_frame *wagptr = (struct wag_data_frame *)packet->buffer;
	uint64_t timestamp = 0;
	timestamp = wagptr->ts.subsecs;
	timestamp |= (uint64_t)wagptr->ts.secs<<32;
	timestamp = ((timestamp%44000000)*(UINT_MAX/44000000)) 
		| ((timestamp/44000000)<<32);
	return timestamp;
}

static int wag_get_capture_length(const struct libtrace_packet_t *packet) {
	struct wag_data_frame *wagptr = (struct wag_data_frame *)packet->buffer;
	return ntohs(wagptr->hdr.size);
}

static int wag_get_wire_length(const struct libtrace_packet_t *packet) {
	struct wag_data_frame *wagptr = (struct wag_data_frame *)packet->buffer;
	return ntohs(wagptr->hdr.size);
}

static struct format_t wag = {
	"wag",
	"$Id$",
	wag_init_input,			/* init_input */	
	NULL,				/* init_output */
	wag_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	NULL,				/* read */
	wag_read_packet,		/* read_packet */
	NULL,				/* write_packet */
	wag_get_link,			/* get_link */
	wag_get_link_type,		/* get_link_type */
	wag_get_direction,		/* get_direction */
	NULL,				/* set_direction */
	wag_get_erf_timestamp,		/* get_wag_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	wag_get_capture_length,		/* get_capture_length */
	wag_get_wire_length,		/* get_wire_length */
	NULL				/* set_capture_length */
};

void __attribute__((constructor)) wag_constructor() {
	register_format(&wag);
}
