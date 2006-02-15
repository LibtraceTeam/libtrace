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

static struct libtrace_format_t wag;
static struct libtrace_format_t wag_trace;

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
		int file;
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
		int file;
#endif
	} output;
};

static int wag_init_input(struct libtrace_t *libtrace) {
	struct stat buf;
	libtrace->format_data = (struct libtrace_format_data_t *) 
		calloc(1,sizeof(struct libtrace_format_data_t));
	CONNINFO.path = libtrace->uridata;
	
	if (stat(CONNINFO.path,&buf) == -1 ) {
		perror("stat");
		return 0;
	}
	if (S_ISCHR(buf.st_mode)) {
		libtrace->sourcetype = TRACE_SOURCE_DEVICE;
				
		INPUT.fd = open(CONNINFO.path, O_RDONLY);

	} else {
		fprintf(stderr, "%s is not a valid char device, exiting\n",
				CONNINFO.path);
		return 0;
		
	}
	return 1;
}

static int wtf_init_input(struct libtrace_t *libtrace) {

	libtrace->format_data = (struct libtrace_format_data_t *)
                calloc(1,sizeof(struct libtrace_format_data_t));
	CONNINFO.path = libtrace->uridata;

	if (!strncmp(CONNINFO.path,"-",1)) {
		/* STDIN */
		libtrace->sourcetype = TRACE_SOURCE_STDIN;
		INPUT.file = LIBTRACE_FDOPEN(fileno(stdin),"r");

	} else {
		/* Do we need this socket stuff at all??
		 * If we do, put it into wag_init_input as it uses
		 * INPUT.fd
		 */

		/*
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
		*/
			/* TRACE */
			libtrace->sourcetype = TRACE_SOURCE_TRACE;
			
			/* we use an FDOPEN call to reopen an FD
			 * returned from open(), so that we can set
			 * O_LARGEFILE. This gets around gzopen not
			 * letting you do this...
			 */
			INPUT.file = LIBTRACE_FDOPEN(open(
					CONNINFO.path,
					O_LARGEFILE), "r");

	}
	return 1;
}


static int wtf_init_output(struct libtrace_out_t *libtrace) {
	char *filemode = 0;
	libtrace->format_data = (struct libtrace_format_data_out_t *)
		calloc(1,sizeof(struct libtrace_format_data_out_t));

	OPTIONS.zlib.level = 0;
	asprintf(&filemode,"wb%d",OPTIONS.zlib.level);
	if (!strncmp(libtrace->uridata,"-",1)) {
		/* STDOUT */
		OUTPUT.file = LIBTRACE_FDOPEN(dup(1), filemode);
	} else {
		/* TRACE */
		OUTPUT.file = LIBTRACE_FDOPEN(open(
					libtrace->uridata,
					O_CREAT | O_LARGEFILE | O_WRONLY,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP), filemode);
	}

	return 1;
}

static int wtf_config_output(struct libtrace_out_t *libtrace, 
		trace_option_output_t option,
		void *value) {
	switch(option) {
#if HAVE_ZLIB
		case TRACE_OPTION_OUTPUT_COMPRESS:
			OPTIONS.zlib.level = *(int*)value;
			assert(OPTIONS.zlib.level>=0 
					&& OPTIONS.zlib.level<=9);
			break;
#else
		case TRACE_OPTION_OUTPUT_COMPRESS:
			/* E feature unavailable */
			return -1;
#endif
		default:
			/* E unknown feature */
			return -1;
	}
}

static int wag_fin_input(struct libtrace_t *libtrace) {
	close(INPUT.fd);
	return 0;
}

static int wtf_fin_input(struct libtrace_t *libtrace) {
	LIBTRACE_CLOSE(INPUT.file);
	return 0;
}

static int wtf_fin_output(struct libtrace_out_t *libtrace) {
	LIBTRACE_CLOSE(OUTPUT.file);
	return 0;
}

static int wag_read(struct libtrace_t *libtrace, void *buffer, size_t len) {
        int numbytes;
        int framesize;
        char *buf_ptr = (char *)buffer;
        int to_read = 0;
        uint16_t magic = 0;
        uint16_t lctr = 0;

        assert(libtrace);

        to_read = sizeof(struct frame_t);

        while (to_read>0) {
          int ret=read(INPUT.fd,buf_ptr,to_read);

          if (ret == -1) {
            if (errno == EINTR || errno==EAGAIN)
              continue;
            perror("read(frame)");
            return -1;
          }

          assert(ret>0);

          to_read = to_read - ret;
          buf_ptr = buf_ptr + ret;
        }

        framesize = ntohs(((struct frame_t *)buffer)->size);
        magic = ntohs(((struct frame_t *)buffer)->magic);

        if (magic != 0xdaa1) {
          printf("Magic number is BAD!\n");
          return -1;
        }

        if (framesize > len) {
          printf("Framesize > len\n");
                return -1;
        }

        buf_ptr = (void*)((char*)buffer + sizeof (struct frame_t));
        to_read = framesize - sizeof(struct frame_t);
        
	while (to_read>0) {
          int ret=read(INPUT.fd,buf_ptr,to_read);

          if (ret == -1) {
            if (errno == EINTR || errno==EAGAIN)
              continue;
            perror("read(frame)");
            return -1;
          }

          to_read = to_read - ret;
          buf_ptr = buf_ptr + ret;
        }
        return framesize;
}


static int wag_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes;
	
        if (packet->buf_control == EXTERNAL) {
                packet->buf_control = PACKET;
                packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
        }
	
	
	packet->trace = libtrace;
	
	if ((numbytes = wag_read(libtrace, (void *)packet->buffer, RP_BUFSIZE)) <= 0) {
	    
    		return numbytes;
	}

	
	packet->size = numbytes;
	packet->header = packet->buffer;
	packet->payload=(char*)packet->buffer+trace_get_framing_length(packet);
	return numbytes;
}

static int wtf_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes;
	void *buffer = packet->buffer;
	void *buffer2 = packet->buffer;
	int framesize;
	int size;

        if (packet->buf_control == EXTERNAL) {
                packet->buf_control = PACKET;
                packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
        }

	
	if ((numbytes = LIBTRACE_READ(INPUT.file, buffer, sizeof(struct frame_t))) == -1) {
		perror("libtrace_read");
		return -1;
	}

	if (numbytes == 0) {
		return 0;
	}

	framesize = ntohs(((struct frame_t *)buffer)->size);
	buffer2 = (char*)buffer + sizeof(struct frame_t);
	size = framesize - sizeof(struct frame_t);
	assert(size < LIBTRACE_PACKET_BUFSIZE);

	
	if ((numbytes=LIBTRACE_READ(INPUT.file, buffer2, size)) != size) {
		perror("libtrace read");
		return -1;
	}

	packet->size = framesize;
	packet->header = packet->buffer;
	packet->payload=(char*)packet->buffer+trace_get_framing_length(packet);
	return framesize;
	
}				
	
static int wtf_write_packet(struct libtrace_out_t *libtrace, const struct libtrace_packet_t *packet) {
	int numbytes =0 ;
	if (packet->trace->format != &wag_trace) {
		fprintf(stderr,"Cannot convert from wag trace format to %s format yet\n",
				packet->trace->format->name);
		return -1;
	}

	/* We could just read from packet->buffer, but I feel it is more technically correct
	 * to read from the header and payload pointers
	 */
	if ((numbytes = LIBTRACE_WRITE(OUTPUT.file, packet->header, trace_get_framing_length(packet))) == 0) {
		perror("libtrace_write");
		return -1;
	}
	if ((numbytes = LIBTRACE_WRITE(OUTPUT.file, packet->payload, 
			packet->size - trace_get_framing_length(packet))) == 0) {
		perror("libtrace_write");
		return -1;
	}
	return numbytes;
}

static libtrace_linktype_t wag_get_link_type(const struct libtrace_packet_t *packet __attribute__((unused))) {
	return TRACE_TYPE_80211;
}

static int8_t wag_get_direction(const struct libtrace_packet_t *packet) {
	struct frame_data_rx_t *wagptr = (struct frame_data_rx_t *)packet->buffer;
	if (wagptr->hdr.type == 0) {
		return wagptr->hdr.subtype;
	}
	return -1;
}

static uint64_t wag_get_erf_timestamp(const struct libtrace_packet_t *packet) {
	struct frame_data_rx_t *wagptr = (struct frame_data_rx_t *)packet->buffer;
	uint64_t timestamp = 0;
	timestamp = ((uint64_t)(ntohl(wagptr->ts.secs)) << 32) | (uint64_t)(ntohl(wagptr->ts.subsecs));
	return timestamp;
}

static int wag_get_capture_length(const struct libtrace_packet_t *packet) {
	struct frame_data_rx_t *wagptr = (struct frame_data_rx_t *)packet->buffer;
	return ntohs(wagptr->hdr.size);
}

static int wag_get_wire_length(const struct libtrace_packet_t *packet) {
	struct frame_data_rx_t *wagptr = (struct frame_data_rx_t *)packet->buffer;
	return ntohs(wagptr->hdr.size);
}

static int wag_get_framing_length(const struct libtrace_packet_t *packet) {
	return sizeof(struct frame_data_rx_t);
}

static int wag_get_fd(const struct libtrace_packet_t *packet) {
	return packet->trace->format_data->input.fd;
}

static struct libtrace_eventobj_t wag_event_trace(struct libtrace_t *trace, struct libtrace_packet_t *packet) {
	switch(trace->sourcetype) {
		case TRACE_SOURCE_DEVICE:
			return trace_event_device(trace,packet);
		default:
			return trace_event_trace(trace,packet);
	}
}
static void wag_help() {
	printf("wag format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\twag:/dev/wagn\n");
	printf("\n");
	printf("\te.g.: wag:/dev/wag0\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\tNone\n");
	printf("\n");
}

static void wtf_help() {
	printf("wag trace format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\twtf:/path/to/trace.wag\n");
	printf("\twtf:/path/to/trace.wag.gz\n");
	printf("\n");
	printf("\te.g.: wtf:/tmp/trace.wag.gz\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\twtf:/path/to/trace.wag\n");
	printf("\twtf:/path/to/trace.wag.gz\n");
	printf("\n");
	printf("\te.g.: wtf:/tmp/trace.wag.gz\n");
	printf("\n");
}

static struct libtrace_format_t wag = {
	"wag",
	"$Id$",
	"wtf",
	wag_init_input,			/* init_input */	
	NULL,				/* config_input */
	NULL,				/* start_input */
	NULL,				/* pause_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	wag_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	wag_read_packet,		/* read_packet */
	NULL,				/* write_packet */
	wag_get_link_type,		/* get_link_type */
	wag_get_direction,		/* get_direction */
	NULL,				/* set_direction */
	wag_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	wag_get_capture_length,		/* get_capture_length */
	wag_get_wire_length,		/* get_wire_length */
	wag_get_framing_length,		/* get_framing_length */
	NULL,				/* set_capture_length */
	wag_get_fd,			/* get_fd */
	wag_event_trace,		/* trace_event */
	wag_help			/* help */
};

/* wtf stands for Wag Trace Format */

static struct libtrace_format_t wag_trace = {
        "wtf",
        "$Id$",
        "wtf",
        wtf_init_input,                 /* init_input */
	NULL,				/* config input */
	NULL,				/* start input */
	NULL,				/* pause_input */
        wtf_init_output,                /* init_output */
        wtf_config_output,              /* config_output */
	NULL,				/* start output */
        wtf_fin_input,                  /* fin_input */
        wtf_fin_output,                 /* fin_output */
        wtf_read_packet,                /* read_packet */
        wtf_write_packet,               /* write_packet */
        wag_get_link_type,              /* get_link_type */
        wag_get_direction,              /* get_direction */
        NULL,                           /* set_direction */
        wag_get_erf_timestamp,          /* get_erf_timestamp */
        NULL,                           /* get_timeval */
        NULL,                           /* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
        wag_get_capture_length,         /* get_capture_length */
        wag_get_wire_length,            /* get_wire_length */
        wag_get_framing_length,         /* get_framing_length */
        NULL,                           /* set_capture_length */
        wag_get_fd,                     /* get_fd */
        wag_event_trace,                /* trace_event */
        wtf_help                        /* help */
};


void __attribute__((constructor)) wag_constructor() {
	register_format(&wag);
	register_format(&wag_trace);
}
