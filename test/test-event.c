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


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include "dagformat.h"
#include "libtrace.h"

struct libtrace_t *trace;

void iferr(libtrace_t *trace)
{
	libtrace_err_t err = trace_get_err(trace);
	if (err.err_num==0)
		return;
	printf("Error: %s\n",err.problem);
	exit(1);
}

int main(int argc UNUSED, char *argv[] UNUSED) {
        char *uri = "erf:traces/100_packets.erf";
	int error = 0;
	int count = 0;
	int running = 1;
	libtrace_packet_t *packet;

	trace = trace_create(uri);
	iferr(trace);

	trace_start(trace);
	iferr(trace);
	
	packet=trace_create_packet();
	while(running) {
		libtrace_eventobj_t ev=trace_event(trace,packet);
		switch(ev.type) {
			case TRACE_EVENT_IOWAIT: {
				fd_set rfd;
				FD_ZERO(&rfd);
				FD_SET(ev.fd,&rfd);
				select(ev.fd+1,&rfd,NULL,NULL,NULL);
			}
			break;
			case TRACE_EVENT_SLEEP: {
				usleep((long)(ev.seconds*1e6));
			}
			break;
			case TRACE_EVENT_PACKET: {
				count ++;
			}
			break;
			case TRACE_EVENT_TERMINATE: {
				running=0;
			}
			break;
		}
		iferr(trace);
        }
	if (packet)
		trace_destroy_packet(packet);
	if (error == 0) {
		if (count == 100) {
			printf("success: 100 packets read\n");
		} else {
			printf("failure: 100 packets expected, %d seen\n",count);
			error = 1;
		}
	} else {
		iferr(trace);
	}
        trace_destroy(trace);
        return error;
}
