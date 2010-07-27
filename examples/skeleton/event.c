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
 * $Id: rate-tracetime.c 551 2005-12-15 01:16:33Z spa1 $
 *
 */





/* This is a simple example program that demonstrates how to use the libtrace
 * event framework. The event framework is ideal for reading from devices and 
 * interfaces in a non-blocking manner, and for reading from a trace in 
 * "tracetime" as opposed to as fast as possible.
 */



#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <libtrace.h>

static void per_packet(libtrace_packet_t *packet) {

	assert(packet);
	/* Your code goes here */
}

static uint32_t event_read_packet(libtrace_t *trace, libtrace_packet_t *packet) 
{
	libtrace_eventobj_t obj;
	fd_set rfds;
	struct timeval sleep_tv;
	
	FD_ZERO(&rfds);
	
	for (;;) {
		obj = trace_event(trace, packet);

		switch(obj.type) {
			
			/* Device has no packets at present - lets wait until
			 * it does get something */
			case TRACE_EVENT_IOWAIT:
				FD_ZERO(&rfds);
				FD_SET(obj.fd, &rfds);
				select(obj.fd + 1, &rfds, NULL, NULL, 0);
				continue;
				
			/* Replaying a trace in tracetime and the next packet
			 * is not due yet */
			case TRACE_EVENT_SLEEP:
				/* select offers good precision for sleeping */
				sleep_tv.tv_sec = (int)obj.seconds;
				sleep_tv.tv_usec = (int) ((obj.seconds - sleep_tv.tv_sec) * 1000000.0);
				select(0, NULL, NULL, NULL, &sleep_tv);
				continue;
				
			/* We've got a packet! */
			case TRACE_EVENT_PACKET:
				/* Check for error first */
				if (obj.size == -1)
					return -1;
				return 1;
				
			/* End of trace has been reached */
			case TRACE_EVENT_TERMINATE:
				return -1;
				
			/* An event we don't know about has occured */
			default:
				fprintf(stderr, "Unknown event type occured\n");
				return -1;
		}
	}
}
		
int main(int argc, char *argv[]) {
	
	libtrace_t *trace;
	libtrace_packet_t *packet;
	int psize = 0;
	char *uri = 0;
	
	if (argc >= 2) {
		uri = strdup(argv[1]);
	} else {
		fprintf(stderr, "Usage: event_example <uri>\n");
		return -1;
	}

	/* Create the trace */
	trace = trace_create(uri);
	if (trace_is_err(trace)) {
		trace_perror(trace, "trace_create");
		return 0;
	}
	
	/* Starting the trace */
	if (trace_start(trace) != 0) {
		trace_perror(trace, "trace_start");
		return 0;
	}

	packet = trace_create_packet();

	for (;;) {
		if ((psize = event_read_packet(trace, packet)) <= 0) {
			break;
		}

		/* Got a packet - let's do something with it */
		per_packet(packet);
	}
	free(uri);
	trace_destroy(trace);
	trace_destroy_packet(packet);
	return 0;

}
