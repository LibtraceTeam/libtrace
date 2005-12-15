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

// 
// This program takes a series of traces and bpf filters and outputs how many
// bytes/packets

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
#include <getopt.h>
#include <inttypes.h>
#include "lt_inttypes.h"

#include "libtrace.h"
#include "tracereport.h"
#include "report.h"

struct libtrace_t *trace;

/* Process a trace, counting packets that match filter(s) */
void run_trace(char *uri) 
{
	struct libtrace_packet_t *packet = trace_create_packet();

	fprintf(stderr,"%s:\n",uri);

        trace = trace_create(uri);

        for (;;) {
		int psize;
                if ((psize = trace_read_packet(trace, packet)) <1) {
                        break;
                }

		error_per_packet(packet);
		port_per_packet(packet);
		protocol_per_packet(packet);
		tos_per_packet(packet);
		ttl_per_packet(packet);
		flow_per_packet(packet);
		dir_per_packet(packet);

        }

        trace_destroy(trace);
}

void usage(char *argv0)
{
	fprintf(stderr,"Usage: %s [--filter|-f bpf ]... libtraceuri...\n",argv0);
}

int main(int argc, char *argv[]) {

	int i;


	for(i=1;i<argc;++i) {
		run_trace(argv[i]);
	}

	error_report();
	flow_report();
	tos_report();
	protocol_report();
	port_report();
	ttl_report();
	dir_report();


        return 0;
}
