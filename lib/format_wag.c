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

#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#ifdef HAVE_SYS_LIMITS_H
#  include <sys/limits.h>
#endif

#ifdef WIN32
#  include <io.h>
#  include <share.h>
#else
#  include <sys/ioctl.h>
#endif

static struct libtrace_format_t wag;
static struct libtrace_format_t wag_trace;

#define DATA(x) 	((struct wag_format_data_t *)x->format_data)
#define DATAOUT(x) 	((struct wag_format_data_out_t *)x->format_data)

#define INPUT DATA(libtrace)->input
#define OUTPUT DATAOUT(libtrace)->output
#define OPTIONS DATAOUT(libtrace)->options

struct wag_format_data_t {
	/** Information about the current state of the input device */
        union {
                int fd;
		libtrace_io_t *file;
        } input;	
};

struct wag_format_data_out_t {
	union {
		struct {
			int level;
			int filemode;
		} zlib;
	} options;
	union {
		int fd;
		libtrace_io_t *file;
	} output;
};

static int wag_init_input(libtrace_t *libtrace) {
	libtrace->format_data = calloc(1, sizeof(struct wag_format_data_t));

	return 0;
}

static int wag_start_input(libtrace_t *libtrace)
{
	struct stat buf;
	if (stat(libtrace->uridata,&buf) == -1 ) {
		trace_set_err(libtrace,errno,"stat(%s)",libtrace->uridata);
		return -1;
	}
#ifndef WIN32
	if (S_ISCHR(buf.st_mode)) {
		INPUT.fd = open(libtrace->uridata, O_RDONLY);
		if (ioctl (INPUT.fd, CAPTURE_RADIOON, 0) == -1) {
			trace_set_err(libtrace, errno,
				"Could not turn WAG radio on");
			return -1;
		}
		return 0;
	}
#endif
	trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,
			"%s is not a valid char device",
			libtrace->uridata);
	return -1;
}

static int wtf_init_input(libtrace_t *libtrace) 
{
	libtrace->format_data = calloc(1,sizeof(struct wag_format_data_t));
	return 0;
}

static int wtf_start_input(libtrace_t *libtrace)
{
	if (DATA(libtrace)->input.file)
		return 0; /* success */
	DATA(libtrace)->input.file = trace_open_file(libtrace);

	if (!DATA(libtrace)->input.file)
		return -1; 

	return 0; /* success */
}

static int wtf_init_output(libtrace_out_t *libtrace) {
	libtrace->format_data = malloc(sizeof(struct wag_format_data_out_t));

	OUTPUT.file = 0;
	OPTIONS.zlib.level = 0;
	OPTIONS.zlib.filemode = O_CREAT | O_WRONLY;
	
	return 0;
}

static int wtf_start_output(libtrace_out_t *libtrace) {
	OUTPUT.file = trace_open_file_out(libtrace,
			OPTIONS.zlib.level,
			OPTIONS.zlib.filemode);
	if (!OUTPUT.file) {
		return -1;
	}
	return 0;
}

static int wtf_config_output(libtrace_out_t *libtrace, 
		trace_option_output_t option,
		void *value) {
	switch(option) {
#ifdef HAVE_LIBZ
		case TRACE_OPTION_OUTPUT_COMPRESS:
			OPTIONS.zlib.level = *(int*)value;
			assert(OPTIONS.zlib.level>=0 
					&& OPTIONS.zlib.level<=9);
			return 0;
#else
		case TRACE_OPTION_OUTPUT_COMPRESS:
			/* E feature unavailable */
			trace_set_err_out(libtrace,TRACE_ERR_OPTION_UNAVAIL,
					"zlib not supported");
			return -1;
#endif
		default:
			/* E unknown feature */
			trace_set_err_out(libtrace,TRACE_ERR_UNKNOWN_OPTION,
					"Unknown option");
			return -1;
	}
}

static int wag_pause_input(libtrace_t *libtrace)
{
	if (ioctl (INPUT.fd, CAPTURE_RADIOON, 0) == -1) {
		trace_set_err(libtrace, errno,
				"Could not turn WAG radio off");
	}
	close(INPUT.fd);
	return 0;
}

static int wag_fin_input(libtrace_t *libtrace) {
	ioctl (INPUT.fd, CAPTURE_RADIOON, 0);
	free(libtrace->format_data);
	return 0;
}

static int wtf_fin_input(libtrace_t *libtrace) {
	libtrace_io_close(INPUT.file);
	free(libtrace->format_data);
	return 0;
}

static int wtf_fin_output(libtrace_out_t *libtrace) {
	libtrace_io_close(OUTPUT.file);
	free(libtrace->format_data);
	return 0;
}

static int wag_read(libtrace_t *libtrace, void *buffer, size_t len, 
		int block) {
        size_t framesize;
        char *buf_ptr = (char *)buffer;
        int to_read = 0;
        uint16_t magic = 0;
	long fd_flags;
	
        assert(libtrace);

        to_read = sizeof(struct frame_t);

#ifndef WIN32
	fd_flags = fcntl(INPUT.fd, F_GETFL);
	if (fd_flags == -1) {
		/* TODO: Replace with better libtrace-style 
		 * error handling later */
		perror("Could not get fd flags");
		return 0;
	}
	
	
	
	if (!block) {
		if (fcntl(INPUT.fd, F_SETFL, fd_flags | O_NONBLOCK) == -1) {
			perror("Could not set fd flags");
			return 0;
		}
	}
	else {
		if (fd_flags & O_NONBLOCK) {
			fd_flags &= ~O_NONBLOCK;
			if (fcntl(INPUT.fd, F_SETFL, fd_flags) == -1) {
				perror("Could not set fd flags");
				return 0;
			}
		}
	}
#endif

	/* I'm not sure if wag has a memory hole which we can use for 
	 * zero-copy - something to add in later, I guess */
	
        while (to_read>0) {
        	int ret=read(INPUT.fd,buf_ptr,to_read);

          	if (ret == -1) {
          	  	if (errno == EINTR)
              			continue;
			
			if (errno == EAGAIN) {
				trace_set_err(libtrace, EAGAIN, "EAGAIN");
				return -1;
			}
	    
	    		trace_set_err(libtrace,errno,
					"read(%s)",libtrace->uridata);
            		return -1;
          	}

          	assert(ret>0);

          	to_read = to_read - ret;
          	buf_ptr = buf_ptr + ret;
        }


        framesize = ntohs(((struct frame_t *)buffer)->size);
        magic = ntohs(((struct frame_t *)buffer)->magic);

        if (magic != 0xdaa1) {
	  trace_set_err(libtrace,
			  TRACE_ERR_BAD_PACKET,"magic number bad or missing");
	  return -1;
        }

	/* We should deal.  this is called "snapping", but we don't yet */
	assert(framesize<=len);

        buf_ptr = (void*)((char*)buffer + sizeof (struct frame_t));
        to_read = framesize - sizeof(struct frame_t);
        
	while (to_read>0) {
          	int ret=read(INPUT.fd,buf_ptr,to_read);

          	if (ret == -1) {
            		if (errno == EINTR) 
              			continue;
			if (errno == EAGAIN) {
				/* What happens to the frame header?! */
				trace_set_err(libtrace, EAGAIN, "EAGAIN");
				return -1;
			}
	    		trace_set_err(libtrace,errno,"read(%s)",
					libtrace->uridata);
            		return -1;
          	}

          	to_read = to_read - ret;
          	buf_ptr = buf_ptr + ret;
        }
        return framesize;
}


static int wag_read_packet_versatile(libtrace_t *libtrace, libtrace_packet_t *packet, int block_flag) {
	int numbytes;
	
        if (packet->buf_control == TRACE_CTRL_EXTERNAL || !packet->buffer) {
                packet->buf_control = TRACE_CTRL_PACKET;
                packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
	}
	
	
	packet->trace = libtrace;
	packet->type = RT_DATA_WAG;
	
	if ((numbytes = wag_read(libtrace, (void *)packet->buffer, 
					RP_BUFSIZE, block_flag)) <= 0) {
	    
    		return numbytes;
	}

	
	packet->header = packet->buffer;
	packet->payload=(char*)packet->buffer+trace_get_framing_length(packet);
	packet->size = trace_get_framing_length(packet) + trace_get_capture_length(packet);
	return numbytes;
}

static int wag_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	return wag_read_packet_versatile(libtrace, packet, 1);
}

static int wtf_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	int numbytes;
	void *buffer;
	void *buffer2;
	int framesize;
	int size;

        if (packet->buf_control == TRACE_CTRL_EXTERNAL || !packet->buffer) {
                packet->buf_control = TRACE_CTRL_PACKET;
                packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
        }
	packet->type = RT_DATA_WAG;
	buffer2 = buffer = packet->buffer;

	numbytes = libtrace_io_read(INPUT.file, buffer, sizeof(struct frame_t));

	if (numbytes == 0) {
		return 0;
	}

	if (numbytes != sizeof(struct frame_t)) {
		int err=errno;
		trace_set_err(libtrace,err,
				"read(%s,frame_t)",packet->trace->uridata);
		printf("failed to read header=%i\n",err);
		return -1;
	}

	if (htons(((struct frame_t *)buffer)->magic) != 0xdaa1) {
		trace_set_err(libtrace,
				TRACE_ERR_BAD_PACKET,"Insufficient magic (%04x)",htons(((struct frame_t *)buffer)->magic));
		return -1;
	}

	framesize = ntohs(((struct frame_t *)buffer)->size);
	buffer2 = (char*)buffer + sizeof(struct frame_t);
	size = framesize - sizeof(struct frame_t);
	assert(size < LIBTRACE_PACKET_BUFSIZE);
	assert(size > 0);
	
	if ((numbytes=libtrace_io_read(INPUT.file, buffer2, size)) != size) {
		trace_set_err(libtrace,
				errno,"read(%s,buffer)",packet->trace->uridata);
		return -1;
	}

	packet->header = packet->buffer;
	packet->payload=(char*)packet->buffer+trace_get_framing_length(packet);
	return framesize;
	
}				
	
static int wtf_write_packet(libtrace_out_t *libtrace, libtrace_packet_t *packet)
{ 
	int numbytes =0 ;
	if (packet->trace->format != &wag_trace) {
		trace_set_err_out(libtrace,TRACE_ERR_NO_CONVERSION,
				"Cannot convert to wag trace format from %s format yet",
				packet->trace->format->name);
		return -1;
	}

	/* We could just read from packet->buffer, but I feel it is more
	 * technically correct to read from the header and payload pointers
	 */
	if ((numbytes = libtrace_io_write(OUTPUT.file, packet->header, 
				trace_get_framing_length(packet))) 
			!=(int)trace_get_framing_length(packet)) {
		trace_set_err_out(libtrace,errno,
				"write(%s)",packet->trace->uridata);
		return -1;
	}
	if ((numbytes = libtrace_io_write(OUTPUT.file, packet->payload, 
				trace_get_capture_length(packet)) 
				!= (int)trace_get_capture_length(packet))) {
		trace_set_err_out(libtrace,
				errno,"write(%s)",packet->trace->uridata);
		return -1;
	}
	return numbytes;
}

static libtrace_linktype_t wag_get_link_type(const libtrace_packet_t *packet UNUSED) {
	return TRACE_TYPE_80211;
}

static libtrace_direction_t wag_get_direction(const libtrace_packet_t *packet) {
	struct frame_data_rx_t *wagptr = (struct frame_data_rx_t *)packet->buffer;
	if (wagptr->hdr.type == 0) {
		return wagptr->hdr.subtype; 
	}
	return -1;
}

static uint64_t wag_get_erf_timestamp(const libtrace_packet_t *packet) {
	struct frame_data_rx_t *wagptr = (struct frame_data_rx_t *)packet->buffer;
	uint64_t timestamp = 0;
	timestamp = ((uint64_t)(ntohl(wagptr->ts.secs)) << 32) | (uint64_t)(ntohl(wagptr->ts.subsecs));
	return timestamp;
}

static int wag_get_capture_length(const libtrace_packet_t *packet) {
	
	struct frame_t * wag_frame_data = (struct frame_t *)packet->header;
	
	if (wag_frame_data->subtype == FRAME_SUBTYPE_DATA_RX) {
		struct frame_data_rx_t *wag_hdr = 
			(struct frame_data_rx_t *)packet->header;
		return ntohs(wag_hdr->rxinfo.length);
	}

	if (wag_frame_data->subtype == FRAME_SUBTYPE_DATA_TX) {
		struct frame_data_tx_t *wag_hdr =
                       (struct frame_data_tx_t *)packet->header;
		return ntohs(wag_hdr->txinfo.length);
	}

	/* default option - not optimal as there tends to be an
	 * extra 2 bytes floating around somewhere */
	return ntohs(((struct frame_t *)packet->header)->size)
		-sizeof(struct frame_data_rx_t);
}

static int wag_get_wire_length(const libtrace_packet_t *packet) {
	struct frame_t * wag_frame_data = (struct frame_t *)packet->header;

	
	if (wag_frame_data->subtype == FRAME_SUBTYPE_DATA_RX) {
		struct frame_data_rx_t *wag_hdr = 
			(struct frame_data_rx_t *)packet->header;
		return ntohs(wag_hdr->rxinfo.length);
	}

	if (wag_frame_data->subtype == FRAME_SUBTYPE_DATA_TX) {
		struct frame_data_tx_t *wag_hdr =
                       (struct frame_data_tx_t *)packet->header;
		return ntohs(wag_hdr->txinfo.length);
	}
	
	/* default option - not optimal as there tends to be an
	 * extra 2 bytes floating around somewhere */
	return ntohs(((struct frame_t *)packet->header)->size)
		-sizeof(struct frame_data_rx_t);
}

static int wag_get_framing_length(UNUSED const libtrace_packet_t *packet) {
	/* There's an extra two bytes floating around somewhere that
	 * we can't account for! */
	return sizeof(struct frame_data_rx_t);
}

static int wag_get_fd(const libtrace_t *trace) {
	return DATA(trace)->input.fd;
}

struct libtrace_eventobj_t trace_event_wag(libtrace_t *trace, libtrace_packet_t *packet) {
	struct libtrace_eventobj_t event = {0,0,0.0,0};
	libtrace_err_t read_err;

	assert(trace);
	assert(packet);

	/* We could probably just call get_fd here */
	if (trace->format->get_fd) {
		event.fd = trace->format->get_fd(trace);
	} else {
		event.fd = 0;
	}
	
	event.size = wag_read_packet_versatile(trace, packet, 0);
	if (event.size == -1) {
		read_err = trace_get_err(trace);
		if (read_err.err_num == EAGAIN) {
			event.type = TRACE_EVENT_IOWAIT;
		}
		else {
			printf("Packet error\n");
			event.type = TRACE_EVENT_PACKET;
		}
	} else if (event.size == 0) {
		event.type = TRACE_EVENT_TERMINATE;
	} else {
		event.type = TRACE_EVENT_PACKET;
	}

	return event;
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
	TRACE_FORMAT_WAG,
	wag_init_input,			/* init_input */	
	NULL,				/* config_input */
	wag_start_input,		/* start_input */
	wag_pause_input,		/* pause_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	wag_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	wag_read_packet,		/* read_packet */
	NULL,				/* fin_packet */
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
	trace_event_wag,		/* trace_event */
	wag_help,			/* help */
	NULL				/* next pointer */
};

/* wtf stands for Wag Trace Format */

static struct libtrace_format_t wag_trace = {
        "wtf",
        "$Id$",
        TRACE_FORMAT_WAG,
	wtf_init_input,                 /* init_input */
	NULL,				/* config input */
	wtf_start_input,		/* start input */
	NULL,				/* pause_input */
        wtf_init_output,                /* init_output */
        wtf_config_output,              /* config_output */
	wtf_start_output,		/* start output */
        wtf_fin_input,                  /* fin_input */
        wtf_fin_output,                 /* fin_output */
        wtf_read_packet,                /* read_packet */
	NULL,				/* fin_packet */
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
        NULL,		                /* get_fd */
        trace_event_trace,              /* trace_event */
        wtf_help,			/* help */
	NULL				/* next pointer */
};


void wag_constructor() {
	register_format(&wag);
	register_format(&wag_trace);
}
