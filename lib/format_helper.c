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
#include "libtrace_int.h"
#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#else
#  error "Can't find inttypes.h - this needs to be fixed"
#endif
#include  "format_helper.h"

#include <sys/ioctl.h>

struct libtrace_eventobj_t trace_event_device(struct libtrace_t *trace, struct libtrace_packet_t *packet) {
	struct libtrace_eventobj_t event = {0,0,0.0,0};
	int data;

	if (packet->trace->format->get_fd) {
		event.fd = packet->trace->format->get_fd(packet);
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

struct libtrace_eventobj_t trace_event_trace(struct libtrace_t *trace, struct libtrace_packet_t *packet) {
	struct libtrace_eventobj_t event = {0,0,0.0,0};
	double ts;
	double now;
	struct timeval stv;

	if (!trace->event.packet.buffer) {
		trace->event.packet.buffer = (void *)malloc(4096);
		trace->event.packet.size=
			trace_read_packet(trace,packet);
		event.size = trace->event.packet.size;
		if (trace->event.packet.size > 0 ) {
			memcpy(trace->event.packet.buffer,
					packet->buffer,
					trace->event.packet.size);
		} else {
			/* return here, the test for
			 * event.size will sort out the error
			 */
			event.type = TRACE_EVENT_TERMINATE;
			return event;
		}
	}

	ts=trace_get_seconds(packet);
	if (trace->event.tdelta!=0) {
		/* Get the adjusted current time */
		gettimeofday(&stv, NULL);
		now = stv.tv_sec + 
			((double)stv.tv_usec / 1000000.0);
		/* adjust for trace delta */
		now -= trace->event.tdelta; 

		/*if the trace timestamp is still in the 
		//future, return a SLEEP event, 
		//otherwise fire the packet
		 */
		if (ts > now) {
			event.seconds = ts - 
				trace->event.trace_last_ts;
			event.type = TRACE_EVENT_SLEEP;
			return event;
		}
	} else {
		gettimeofday(&stv, NULL);
		/* work out the difference between the 
		// start of trace replay, and the first
		// packet in the trace
		 */
		trace->event.tdelta = stv.tv_sec + 
			((double)stv.tv_usec / 1000000.0);
		trace->event.tdelta -= ts;
	}

	/* This is the first packet, so just fire away. */
	packet->size = trace->event.packet.size;
	memcpy(packet->buffer,
			trace->event.packet.buffer,
			trace->event.packet.size);
	free(trace->event.packet.buffer);
	trace->event.packet.buffer = 0;
	event.type = TRACE_EVENT_PACKET;

	trace->event.trace_last_ts = ts;

	return event;
	
}
