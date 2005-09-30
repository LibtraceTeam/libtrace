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
// This program takes a trace and outputs every packet that it sees to standard
// out, decoding source/dest IP's, protocol type, and the timestamp of this
// packet.

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

#include "libtrace.h"

struct libtrace_t *trace;

struct filter_t {
	char *expr;
	struct libtrace_filter_t *filter;
	uint64_t count;
	uint64_t bytes;
} *filters = NULL;
int filter_count=0;
uint64_t count;
uint64_t bytes;

/* Process a trace, counting packets that match filter(s) */
void run_trace(char *uri) 
{
	struct libtrace_packet_t packet;
	int i;

	fprintf(stderr,"%s:\n",uri);

        trace = trace_create(uri);

        for (;;) {
		int psize;
                if ((psize = trace_read_packet(trace, &packet)) <1) {
                        break;
                }

		for(i=0;i<filter_count;++i) {
			if(trace_bpf_filter(filters[i].filter,&packet)) {
				++filters[i].count;
				filters[i].bytes+=trace_get_wire_length(&packet);
			}
		}

		++count;
		bytes+=trace_get_wire_length(&packet);
        }

	for(i=0;i<filter_count;++i) {
		printf("%s\t%8"PRIu64"\t%8"PRIu64"\t%5.02f\n",filters[i].expr,filters[i].count,filters[i].bytes,filters[i].count*100.0/count);
		filters[i].bytes=0;
		filters[i].count=0;
	}
	printf("Total:\t%8"PRIu64"\t%8" PRIu64 "\n",count,bytes);
	count=0;
	bytes=0;

        trace_destroy(trace);
}

void usage(char *argv0)
{
	fprintf(stderr,"Usage: %s [--filter|-f bpf ]... libtraceuri...\n",argv0);
}

int main(int argc, char *argv[]) {

	int i;

	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",	1, 0, 'f' },
			{ NULL, 	0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "f:",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 'f': 
				++filter_count;
				filters=realloc(filters,filter_count*sizeof(struct filter_t));
				filters[filter_count-1].expr=strdup(optarg);
				filters[filter_count-1].filter=trace_bpf_setfilter(optarg);
				filters[filter_count-1].count=0;
				filters[filter_count-1].bytes=0;
				break;
			default:
				fprintf(stderr,"Unknown option: %c\n",c);
				usage(argv[0]);
				return 1;
		}
	}

	printf("filter\tcount    \tbytes   \t%%\n");
	for(i=optind;i<argc;++i) {
		run_trace(argv[i]);
	}


        return 0;
}
