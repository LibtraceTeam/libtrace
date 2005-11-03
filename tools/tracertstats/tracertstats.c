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
// bytes/packets every time interval

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
#include "output.h"

struct libtrace_t *trace;
char *output_format=NULL;

struct filter_t {
	char *expr;
	struct libtrace_filter_t *filter;
	uint64_t count;
	uint64_t bytes;
} *filters = NULL;
int filter_count=0;
uint64_t totcount;
uint64_t totbytes;

uint64_t packet_count=UINT64_MAX;
uint64_t packet_interval=UINT64_MAX;


struct output_data_t *output;

void report_results(double ts,uint64_t count,uint64_t bytes)
{
	int i=0;
	output_set_data_time(output,0,ts);
	output_set_data_int(output,1,count);
	output_set_data_int(output,2,bytes);
	for(i=0;i<filter_count;++i) {
		output_set_data_int(output,i*2+3,filters[i].count);
		output_set_data_int(output,i*2+4,filters[i].bytes);
		filters[i].count=filters[i].bytes=0;
	}
	output_flush_row(output);
}

/* Process a trace, counting packets that match filter(s) */
void run_trace(char *uri) 
{
	struct libtrace_packet_t packet;
	int i;
	uint64_t count = 0;
	uint64_t bytes = 0;
	double last_ts = 0;
	double ts = 0;

	output=output_init(uri,output_format?:"csv");
	output_add_column(output,"unix_time");
	output_add_column(output,"packets");
	output_add_column(output,"bytes");
	for(i=0;i<filter_count;++i) {
		char buff[1024];
		snprintf(buff,sizeof(buff),"%s packets",filters[i].expr);
		output_add_column(output,buff);
		snprintf(buff,sizeof(buff),"%s bytes",filters[i].expr);
		output_add_column(output,buff);
	}
	output_flush_headings(output);


        trace = trace_create(uri);

        for (;;) {
		int psize;
                if ((psize = trace_read_packet(trace, &packet)) <1) {
                        break;
                }
		ts = trace_get_seconds(&packet);

		for(i=0;i<filter_count;++i) {
			if(trace_bpf_filter(filters[i].filter,&packet)) {
				++filters[i].count;
				filters[i].bytes+=trace_get_wire_length(&packet);
			}
		}

		++count;
		bytes+=trace_get_wire_length(&packet);

		if (packet_interval!=UINT64_MAX
		  &&(last_ts==0 || last_ts<ts)) {
			if (last_ts==0)
				last_ts=ts;
			report_results(ts,count,bytes);
			count=0;
			bytes=0;
			last_ts+=packet_interval;
		}

		if (count > packet_count) {
			report_results(ts,count,bytes);
			count=0;
			bytes=0;
		}
        }
	report_results(ts,count,bytes);

        trace_destroy(trace);
	output_destroy(output);
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
			{ "interval",	1, 0, 'i' },
			{ "count",	1, 0, 'c' },
			{ "output-format",1,0,'o' },
			{ NULL, 	0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "c:f:i:o:",
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
			case 'i':
				packet_interval=atoi(optarg);
				break;
			case 'c':
				packet_interval=atoi(optarg);
				break;
			case 'o':
				if (output_format) free(output_format);
				output_format=strdup(optarg);
				break;
			default:
				fprintf(stderr,"Unknown option: %c\n",c);
				usage(argv[0]);
				return 1;
		}
	}

	if (packet_count == UINT64_MAX && packet_interval == UINT64_MAX) {
		packet_interval = 300; /* every 5 minutes */
	}

	for(i=optind;i<argc;++i) {
		run_trace(argv[i]);
	}

        return 0;
}
