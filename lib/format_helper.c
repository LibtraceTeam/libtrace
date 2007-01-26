/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007 The University of Waikato, Hamilton, New Zealand.
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

#include "config.h"
#include <sys/types.h>
#include <fcntl.h> /* for O_LARGEFILE */
#include <math.h>
#include "libtrace.h"
#include "libtrace_int.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "format_helper.h"

#include <assert.h>
#include <stdarg.h>

#ifdef WIN32
#  include <io.h>
#  include <share.h>
#  include <sys/timeb.h>

struct libtrace_eventobj_t trace_event_device(struct libtrace_t *trace, struct libtrace_packet_t *packet) {
    struct libtrace_eventobj_t event = {0,0,0.0,0};

    trace_set_err(trace,TRACE_ERR_OPTION_UNAVAIL, "trace_event() is not "
            "supported on devices under windows in this version");

    event.type = TRACE_EVENT_TERMINATE;
    return event;
}
#else
#  include <sys/ioctl.h>

struct libtrace_eventobj_t trace_event_device(struct libtrace_t *trace, 
					struct libtrace_packet_t *packet) {
	struct libtrace_eventobj_t event = {0,0,0.0,0};
	int data;

	assert(trace != NULL);
	assert(packet != NULL);
	
	if (trace->format->get_fd) {
		event.fd = trace->format->get_fd(trace);
	} else {
		event.fd = 0;
	}
	if (ioctl(event.fd,FIONREAD,&data)==-1) {
		event.type = TRACE_EVENT_TERMINATE;
		return event;
	} 
		
	if (data>0) {
		event.size = trace_read_packet(trace,packet);
		event.type = TRACE_EVENT_PACKET;
		return event;
	}
	event.type= TRACE_EVENT_IOWAIT;
	return event;
}
#endif

struct libtrace_eventobj_t trace_event_trace(struct libtrace_t *trace, struct libtrace_packet_t *packet) {
	struct libtrace_eventobj_t event = {0,0,0.0,0};
	double ts;
	double now;
#ifdef WIN32
	struct __timeb64 tstruct;
#else
	struct timeval stv;
#endif

	if (!trace->event.packet) {
		trace->event.packet = trace_create_packet();
		trace->event.psize=
			trace_read_packet(trace,trace->event.packet);
		if (trace->event.psize<1) {
			/* return here, the test for
			 * event.size will sort out the error
			 */
			if (trace_is_err(trace)) {
				trace_perror(trace, "read packet");
			}
			event.type = TRACE_EVENT_TERMINATE;
			return event;
		}
	}

	ts=trace_get_seconds(trace->event.packet);

	/* Get the adjusted current time */
#ifdef WIN32
	_ftime64(&tstruct);
	now = tstruct.time + 
		((double)tstruct.millitm / 1000.0);
#else
	gettimeofday(&stv, NULL);
	now = stv.tv_sec + 
		((double)stv.tv_usec / 1000000.0);
#endif

	if (fabs(trace->event.tdelta)<1e-9) {
		/* adjust for trace delta */
		now -= trace->event.tdelta; 

		/* if the trace timestamp is still in the 
		 * future, return a SLEEP event, 
		 * otherwise fire the packet
		 */
		if (ts > now) {
			event.seconds = ts - 
				trace->event.trace_last_ts;
			event.type = TRACE_EVENT_SLEEP;
			return event;
		}
	} else {
		/* work out the difference between the 
		 * start of trace replay, and the first
		 * packet in the trace
		 */
		trace->event.tdelta = now - ts;
	}

	/* This is the first packet, so just fire away. */
	/* TODO: finalise packet */
	
	/* XXX: Could we do this more efficiently? */
	/* We do a lot of freeing and creating of packet buffers with this
	 * method, but at least it works unlike what was here previously */
	if (packet->buf_control == TRACE_CTRL_PACKET) {
		free(packet->buffer);
	}
		
	packet->type = trace->event.packet->type;
	packet->trace = trace->event.packet->trace;
	packet->header = trace->event.packet->header;
	packet->payload = trace->event.packet->payload;
	
	packet->buffer = trace->event.packet->buffer;
	packet->buf_control = trace->event.packet->buf_control;

	trace->event.packet->buf_control = TRACE_CTRL_EXTERNAL;
	
	trace_destroy_packet(trace->event.packet);
	trace->event.packet = NULL;

	event.type = TRACE_EVENT_PACKET;

	trace->event.trace_last_ts = ts;

	return event;
}

/* Catch undefined O_LARGEFILE on *BSD etc */
#ifndef O_LARGEFILE
#  define O_LARGEFILE 0
#endif 

/* Catching O_BINARY on all sane OS's */
#ifndef O_BINARY
#  define O_BINARY 0
#endif

/* open a file or stdin using gzip compression if necessary (and supported)
 * @internal
 */
libtrace_io_t *trace_open_file(libtrace_t *trace)
{
	int fd;
	libtrace_io_t *ret;


	if (strcmp(trace->uridata,"-")==0) {
		ret=libtrace_io_fdopen(fileno(stdin),"rb");
		return ret;
	}

	/* We open the file with open(2), so we can provide O_LARGEFILE
	 * as zlib doesn't always do it itself
	 */
	fd=open(trace->uridata,O_LARGEFILE|O_RDONLY|O_BINARY);
	if (fd==-1) {
		trace_set_err(trace,errno,"Unable to open %s",trace->uridata);
		return 0;
	}
	ret=libtrace_io_fdopen(fd,"rb");
	return ret;
}

/* Create a file or write to stdout using compression if requested
 * @internal
 */
libtrace_io_t *trace_open_file_out(libtrace_out_t *trace,int level, int fileflag)
{
	int fd;
	libtrace_io_t *ret;
	char filemode[4]; /* wb9\0 */
	assert(level<10);
	assert(level>=0);
#ifdef HAVE_LIBZ
	snprintf(filemode,sizeof(filemode),"wb%d",level);
#else
	snprintf(filemode,sizeof(filemode),"wb");
#endif

	if (strcmp(trace->uridata,"-")==0) {
		ret=libtrace_io_fdopen(fileno(stdout),filemode);
		return ret;
	}

	/* We open the file with open(2), so we can provide O_LARGEFILE
	 * as zlib doesn't always do it itself
	 */
	fd=open(trace->uridata,fileflag|O_LARGEFILE|O_BINARY,0666);
	if (fd==-1) {
		trace_set_err_out(trace,
				errno,"Unable to open %s",trace->uridata);
		return 0;
	}
	ret=libtrace_io_fdopen(fd,filemode);
	if (!ret) {
		printf("%s\n",filemode);
		trace_set_err_out(trace,
				TRACE_ERR_INIT_FAILED,"gz out of memory");
	}
	return ret;
}


/** Update the libtrace error
 * @param errcode either an Econstant from libc, or a LIBTRACE_ERROR
 * @param msg a plaintext error message
 * @internal
 */
void trace_set_err(libtrace_t *trace,int errcode,const char *msg,...)
{
	char buf[256];
	va_list va;
	va_start(va,msg);
	assert(errcode != 0 && "An error occurred, but it is unknown what it is");
	trace->err.err_num=errcode;
	if (errcode>0) {
		vsnprintf(buf,sizeof(buf),msg,va);
		snprintf(trace->err.problem,sizeof(trace->err.problem),
				"%s: %s",buf,strerror(errcode));
	} else {
		vsnprintf(trace->err.problem,sizeof(trace->err.problem),
				msg,va);
	}
	va_end(va);
}

/** Update the libtrace for output traces error
 * @param errcode either an Econstant from libc, or a LIBTRACE_ERROR
 * @param msg a plaintext error message
 * @internal
 */
void trace_set_err_out(libtrace_out_t *trace,int errcode,const char *msg,...)
{
	char buf[256];
	va_list va;
	va_start(va,msg);
	assert(errcode != 0 && "An error occurred, but it is unknown what it is");
	trace->err.err_num=errcode;
	if (errcode>0) {
		vsnprintf(buf,sizeof(buf),msg,va);
		snprintf(trace->err.problem,sizeof(trace->err.problem),
				"%s: %s",buf,strerror(errno));
	} else {
		vsnprintf(trace->err.problem,sizeof(trace->err.problem),
				msg,va);
	}
	va_end(va);
}

uint64_t byteswap64(uint64_t num)
{
	return (byteswap32((num&0xFFFFFFFF00000000ULL)>>32))
	      |((uint64_t)byteswap32(num&0x00000000FFFFFFFFULL)<<32);
}

uint32_t byteswap32(uint32_t num)
{
	return ((num&0x000000FFU)<<24)
		| ((num&0x0000FF00U)<<8)
		| ((num&0x00FF0000U)>>8)
		| ((num&0xFF000000U)>>24);
}

uint16_t byteswap16(uint16_t num)
{
	return ((num<<8)&0xFF00)|((num>>8)&0x00FF);
}

