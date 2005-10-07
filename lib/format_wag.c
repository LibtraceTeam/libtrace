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
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "wag.h"
#include "config.h"

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
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#ifdef HAVE_SYS_LIMITS_H
#  include <sys/limits.h>
#endif

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

static struct libtrace_format_t *wag_ptr = 0;

#define CONNINFO libtrace->format_data->conn_info
#define INPUT libtrace->format_data->input
#define OUTPUT libtrace->format_data->output
#define OPTIONS libtrace->format_data->options

struct libtrace_format_data_t {
	union {
		/** Information about rtclients */
                struct {
                        char *hostname;
                        short port;
                } rt;
                char *path;		/**< information for local sockets */
        } conn_info;
	/** Information about the current state of the input device */
        union {
                int fd;
#if HAVE_ZLIB
                gzFile *file;
#else	
		FILE *file;
#endif
        } input;	
};

struct libtrace_format_data_out_t {
	union {
		char *path;
	} conn_info;
	union {
		struct {
			int level;
		} zlib;
	} options;
	union {
		int fd;
#if HAVE_ZLIB
		gzFile *file;
#else
		FILE *file;
#endif
	} output;
};

static int wag_init_input(struct libtrace_t *libtrace) {
	struct stat buf;
	struct sockaddr_un unix_sock;
	libtrace->format_data = (struct libtrace_format_data_t *) 
		calloc(1,sizeof(struct libtrace_format_data_t));
	CONNINFO.path = libtrace->uridata;
	if (!strncmp(CONNINFO.path,"-",1)) {
		libtrace->sourcetype = STDIN;
		// STDIN
#if HAVE_ZLIB
		INPUT.file = gzdopen(STDIN, "r");
#else	
		INPUT.file = stdin;
#endif

	} else {
		if (stat(CONNINFO.path,&buf) == -1 ) {
			perror("stat");
			return 0;
		}
		if (S_ISSOCK(buf.st_mode)) {
			libtrace->sourcetype = SOCKET;
			// SOCKET
			if ((INPUT.fd = socket(
					AF_UNIX, SOCK_STREAM, 0)) == -1) {
				perror("socket");
				return 0;
			}
			unix_sock.sun_family = AF_UNIX;
			bzero(unix_sock.sun_path,108);
			snprintf(unix_sock.sun_path,
					108,"%s"
					,CONNINFO.path);

			if (connect(INPUT.fd, 
					(struct sockaddr *)&unix_sock,
					sizeof(struct sockaddr)) == -1) {
				perror("connect (unix)");
				return 0;
			}
		} else { 
			// TRACE
			libtrace->sourcetype = TRACE;
#if HAVE_ZLIB
			// using gzdopen means we can set O_LARGEFILE
			// ourselves. However, this way is messy and 
			// we lose any error checking on "open"
			INPUT.file = 
				gzdopen(open(
					CONNINFO.path,
					O_LARGEFILE), "r");
#else
			INPUT.file = 
				fdopen(open(
					CONNINFO.path,
					O_LARGEFILE), "r");
#endif

		}
	}
	return 1;
}

static int wag_init_output(struct libtrace_out_t *libtrace) {
	char *filemode = 0;
	libtrace->format_data = (struct libtrace_format_data_out_t *)
		calloc(1,sizeof(struct libtrace_format_data_out_t));

	OPTIONS.zlib.level = 0;
	asprintf(&filemode,"wb%d",OPTIONS.zlib.level);
	if (!strncmp(libtrace->uridata,"-",1)) {
		// STDOUT				
#if HAVE_ZLIB
		OUTPUT.file = gzdopen(dup(1), filemode);
#else
		OUTPUT.file = stdout;
#endif
	} else {
		// TRACE
#if HAVE_ZLIB
		OUTPUT.file = gzdopen(open(
					libtrace->uridata,
					O_CREAT | O_LARGEFILE | O_WRONLY,
					S_IRUSR | S_IWUSR), filemode);
#else
		OUTPUT.file = fdopen(open(
					O_CREAT | O_LARGEFILE | O_WRONLY,
					S_IRUSR | S_IWUSR), "w");
#endif
	}

	return 1;
}

static int wag_config_output(struct libtrace_out_t *libtrace, int argc, char *argv[]) {
#if HAVE_ZLIB
	int opt;
	int level = OPTIONS.zlib.level;
	optind = 1;
	while ((opt = getopt(argc, argv, "z:")) != EOF) {
		switch (opt) {
			case 'z':
				level = atoi(optarg);
				break;
			default:
				printf("Bad argument to wag: %s\n", optarg);
				return -1;
		}
	}
	if (level != OPTIONS.zlib.level) {
		if (level > 9 || level < 0) {
			// retarded level choice
			printf("Compression level must be between 0 and 9 inclusive - you selected %i \n", level);
		} else {
			OPTIONS.zlib.level = level;
			return gzsetparams(OUTPUT.file, level, Z_DEFAULT_STRATEGY);
		}
	}
#endif
	return 0;
}

static int wag_fin_input(struct libtrace_t *libtrace) {
#if HAVE_ZLIB
	gzclose(INPUT.file);
#else	
	fclose(INPUT.file);	
#endif
	return 0;
}

static int wag_fin_output(struct libtrace_out_t *libtrace) {
#if HAVE_ZLIB
	gzclose(OUTPUT.file);
#else
	fclose(OUTPUT.file);
#endif
	return 0;
}

static int wag_read(struct libtrace_t *libtrace, void *buffer, size_t len) {
        int numbytes;
	assert(libtrace);

        if (buffer == 0)
                buffer = malloc(len);

	while(1) {
		switch(libtrace->sourcetype) {
			case DEVICE:
				if ((numbytes=read(INPUT.fd, 
								buffer, 
								len)) == -1) {
					perror("read");
					return -1;
				}
				break;
			default:
#if HAVE_ZLIB
				if ((numbytes=gzread(INPUT.file,
								buffer,
								len)) == -1) {
					perror("gzread");
					return -1;
				}
#else
				if ((numbytes=fread(buffer,len,1,
					INPUT.file)) == 0 ) {
					if(feof(INPUT.file)) {
						return 0;
					}
					if(ferror(INPUT.file)) {
						perror("fread");
						return -1;
					}
					return 0;
				}
#endif
		}
		break;
	}
        return numbytes;

}


static int wag_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes;
	int size;
	char buf[RP_BUFSIZE];
	int read_required = 0;

	void *buffer = 0;

	packet->trace = libtrace;
	buffer = packet->buffer;
	

	do {
		if (tracefifo_out_available(libtrace->fifo) == 0 || read_required) {
			if ((numbytes = wag_read(libtrace,buf,RP_BUFSIZE)) <= 0) {
				return numbytes;
			}
			assert(libtrace->fifo);
			tracefifo_write(libtrace->fifo,buf,numbytes);
			read_required = 0;
		}
		// read in wag_frame_hdr
		if ((numbytes = tracefifo_out_read(libtrace->fifo, 
						buffer,
						sizeof(struct wag_frame_hdr)))
				== 0 ) {
			tracefifo_out_reset(libtrace->fifo);
			read_required = 1;
			continue;
		}
		
		size = ntohs(((struct wag_frame_hdr *)buffer)->size);

		// wag isn't in network byte order yet
		//size = htons(size);
		//printf("%d %d\n",size,htons(size));

		// read in full packet
		if((numbytes = tracefifo_out_read(libtrace->fifo,buffer,size)) == 0) {
			tracefifo_out_reset(libtrace->fifo);
			read_required = 1;
			continue;
		}

		// have the whole packet
		tracefifo_out_update(libtrace->fifo,size);
		tracefifo_ack_update(libtrace->fifo,size);

		packet->status = 0;
		packet->size = numbytes;
		return numbytes;
	} while(1);
}

static int wag_write_packet(struct libtrace_out_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes =0 ;
	if (packet->trace->format != wag_ptr) {
		fprintf(stderr,"Cannot convert from wag to %s format yet\n",
				packet->trace->format->name);
		return -1;
	}
#if HAVE_ZLIB
	if ((numbytes = gzwrite(OUTPUT.file, packet->buffer, packet->size)) == 0) {
		perror("gzwrite");
		return -1;
	}
#else
	if ((numbytes = write(OUTPUT.file, packet->buffer, packet->size)) == 0) {
		perror("write");
		return -1;
	}
#endif
	return numbytes;
}

static void *wag_get_link(const struct libtrace_packet_t *packet) {
	struct wag_data_frame *wagptr = (struct wag_data_frame *)packet->buffer;
	void *payload = wagptr->data;
	return (void*)payload;
}

static libtrace_linktype_t wag_get_link_type(const struct libtrace_packet_t *packet __attribute__((unused))) {
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
	//timestamp |= (uint64_t)wagptr->ts.secs<<32;
	timestamp = ((timestamp%44000000)*(UINT_MAX/44000000)) 
		| ((timestamp/44000000)<<32);
	return timestamp;
}

static int wag_get_capture_length(const struct libtrace_packet_t *packet) {
	struct wag_data_frame *wagptr = (struct wag_data_frame *)packet->buffer;
	//return (wagptr->hdr.size);
	return ntohs(wagptr->hdr.size);
}

static int wag_get_wire_length(const struct libtrace_packet_t *packet) {
	struct wag_data_frame *wagptr = (struct wag_data_frame *)packet->buffer;
	//return (wagptr->hdr.size);
	return ntohs(wagptr->hdr.size);
}

static int wag_get_fd(const struct libtrace_packet_t *packet) {
	return packet->trace->format_data->input.fd;
}

static struct libtrace_eventobj_t wag_event_trace(struct libtrace_t *trace, struct libtrace_packet_t *packet) {
	switch(trace->sourcetype) {
		case DEVICE:
			return trace_event_device(trace,packet);
		default:
			return trace_event_trace(trace,packet);
	}
}
static void wag_help() {
	printf("wag format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\twag:/dev/wagn\n");
	printf("\twag:/path/to/trace.wag\n");
	printf("\twag:/path/to/trace.wag.gz\n");
	printf("\n");
	printf("\te.g.: wag:/dev/wag0\n");
	printf("\te.g.: wag:/tmp/trace.wag.gz\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\tnone\n");
	printf("\n");
}

static struct libtrace_format_t wag = {
	"wag",
	"$Id$",
	"wag",
	wag_init_input,			/* init_input */	
	wag_init_output,		/* init_output */
	wag_config_output,		/* config_output */
	wag_fin_input,			/* fin_input */
	wag_fin_output,			/* fin_output */
	wag_read_packet,		/* read_packet */
	wag_write_packet,		/* write_packet */
	wag_get_link,			/* get_link */
	wag_get_link_type,		/* get_link_type */
	wag_get_direction,		/* get_direction */
	NULL,				/* set_direction */
	wag_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	wag_get_capture_length,		/* get_capture_length */
	wag_get_wire_length,		/* get_wire_length */
	NULL,				/* set_capture_length */
	wag_get_fd,			/* get_fd */
	wag_event_trace,		/* trace_event */
	wag_help			/* help */
};

void __attribute__((constructor)) wag_constructor() {
	wag_ptr = &wag;
	register_format(wag_ptr);
}
