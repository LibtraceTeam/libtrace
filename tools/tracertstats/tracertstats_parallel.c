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

/* This program takes a series of traces and bpf filters and outputs how many
 * bytes/packets every time interval
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
#include <getopt.h>
#include <inttypes.h>
#include <lt_inttypes.h>

#include "libtrace.h"
#include "output.h"
#include "rt_protocol.h"
#include "dagformat.h"

#include "data-struct/vector.h"
#include "data-struct/message_queue.h"

#ifndef UINT32_MAX
	#define UINT32_MAX      0xffffffffU
#endif

#define DEFAULT_OUTPUT_FMT "txt"

struct libtrace_t *trace;
char *output_format=NULL;

int merge_inputs = 0;

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
double packet_interval=UINT32_MAX;


struct output_data_t *output = NULL;

static void report_results(double ts,uint64_t count,uint64_t bytes)
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

static void create_output(char *title) {
	int i;
	
	output=output_init(title,output_format?output_format:DEFAULT_OUTPUT_FMT);
	if (!output) {
		fprintf(stderr,"Failed to create output file\n");
		return;
	}
	output_add_column(output,"ts");
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

}

uint64_t count;
uint64_t bytes;

typedef struct statistic {
	uint64_t count;
	uint64_t bytes;
} statistic_t;

typedef struct result {
	struct statistic total;
	struct statistic filters[0];
} result_t;

static uint64_t last_ts = 0;
static void process_result(libtrace_t *trace UNUSED, libtrace_result_t *result, libtrace_message_t *mesg UNUSED)  {
	static uint64_t ts = 0;

	if (result) {
		int j;
		result_t *res;
		ts = libtrace_result_get_key(result);
		res = libtrace_result_get_value(result);
		if (last_ts == 0)
			last_ts = ts;
		while (last_ts < ts) {
			report_results((double) last_ts * (double) packet_interval, count, bytes);
			count = 0;
			bytes = 0;
			for (j = 0; j < filter_count; j++)
				filters[j].count = filters[j].bytes = 0;
			last_ts++;
		}
		count += res->total.count;
		bytes += res->total.bytes;
		for (j = 0; j < filter_count; j++) {
			filters[j].count += res->filters[j].count;
			filters[j].bytes += res->filters[j].bytes;
		}
		free(res);
	}
}

typedef struct timestamp_sync {
	int64_t difference_usecs;
	uint64_t first_interval_number;
} timestamp_sync_t;

static void* per_packet(libtrace_t *trace, libtrace_packet_t *pkt, 
						libtrace_message_t *mesg,
						libtrace_thread_t *t)
{
	int i;
	static __thread uint64_t last_ts = 0, ts = 0;
	static __thread result_t * results = NULL;
	
	// Unsure when we would hit this case but the old code had it, I 
	// guess we should keep it
	if (pkt && trace_get_packet_buffer(pkt,NULL,NULL) != NULL) {
		//fprintf(stderr, "Got packet t=%x\n", t);
		ts = trace_get_seconds(pkt) / packet_interval;
		if (last_ts == 0)
			last_ts = ts;

		while (packet_interval != UINT64_MAX && last_ts<ts) {
			// Publish and make a new one new
			//fprintf(stderr, "Publishing result %"PRIu64"\n", last_ts);
			trace_publish_result(trace, t, (uint64_t) last_ts, results, RESULT_NORMAL);
			trace_post_reporter(trace);
			results = calloc(1, sizeof(result_t) + sizeof(statistic_t) * filter_count);
			last_ts++;
		}
		
		for(i=0;i<filter_count;++i) {
			if(trace_apply_filter(filters[i].filter, pkt)) {
				results->filters[i].count++;
				results->filters[i].bytes+=trace_get_wire_length(pkt);
			}
		}
		
		results->total.count++;
		results->total.bytes +=trace_get_wire_length(pkt);
		/*if (count >= packet_count) {
			report_results(ts,count,bytes);
			count=0;
			bytes=0;
		}*/ // TODO what was happening here doesn't match up with any of the documentations!!!
	}
	
	if (mesg) {
		// printf ("%d.%06d READ #%"PRIu64"\n", tv.tv_sec, tv.tv_usec, trace_packet_get(packet));
		switch (mesg->code) {
			case MESSAGE_STARTING:
				results = calloc(1, sizeof(result_t) + sizeof(statistic_t) * filter_count);
				break;
			case MESSAGE_STOPPING:
				// Should we always post this?
				if (results->total.count) {
					trace_publish_result(trace, t, (uint64_t) last_ts, results, RESULT_NORMAL);
					trace_post_reporter(trace);
					results = NULL;
				}
				break;
			case MESSAGE_TICK:
			{
				int64_t offset;
				struct timeval *tv, tv_real;
				libtrace_packet_t *first_packet = NULL;
				retrive_first_packet(trace, &first_packet, &tv);
				if (first_packet != NULL) {
					// So figure out our running offset
					tv_real = trace_get_timeval(first_packet);
					offset = tv_to_usec(tv) - tv_to_usec(&tv_real);
					// Get time of day and do this stuff
					uint64_t next_update_time;
					next_update_time = (last_ts*packet_interval + packet_interval) * 1000000 + offset;
					if (next_update_time <= mesg->additional.uint64) {
						//fprintf(stderr, "Got a tick and publishing early!!\n");
						trace_publish_result(trace, t, (uint64_t) last_ts, results, RESULT_NORMAL);
						trace_post_reporter(trace);
						results = calloc(1, sizeof(result_t) + sizeof(statistic_t) * filter_count);
						last_ts++;
					} else {
						//fprintf(stderr, "Got a tick but no publish ...\n");
					}
				} else {
					//fprintf(stderr, "Got a tick but no packets seen yet!!!\n");
				}
			}
		}
	}
	return pkt;
}

static uint64_t bad_hash(const libtrace_packet_t * pkt UNUSED, void *data UNUSED) {
	return 0;
}

/* Process a trace, counting packets that match filter(s) */
static void run_trace(char *uri)
{
	int j;

	if (!merge_inputs) 
		create_output(uri);

	if (output == NULL)
		return;

        trace = trace_create(uri);
	if (trace_is_err(trace)) {
		trace_perror(trace,"trace_create");
		trace_destroy(trace);
		if (!merge_inputs)
			output_destroy(output);
		return;
	}
	/*
	if (trace_start(trace)==-1) {
		trace_perror(trace,"trace_start");
		trace_destroy(trace);
		if (!merge_inputs)
			output_destroy(output);
		return;
	}*/
	int i = 1;
	trace_parallel_config(trace, TRACE_OPTION_ORDERED, &i);
	/* trace_parallel_config(trace, TRACE_OPTION_TRACETIME, &i); */
	//trace_set_hasher(trace, HASHER_CUSTOM, &bad_hash, NULL);

	if (trace_get_information(trace)->live) {
		i = (int) (packet_interval * 1000); // Every interval send a tick
		trace_parallel_config(trace, TRACE_OPTION_TICK_INTERVAL, &i);
	}

	if (trace_pstart(trace, NULL, &per_packet, process_result)==-1) {
		trace_perror(trace,"Failed to start trace");
		trace_destroy(trace);
		if (!merge_inputs)
			output_destroy(output);
		return;
	}


	// Wait for all threads to stop
	trace_join(trace);
	
	// Flush the last one out
	report_results((double) last_ts * (double) packet_interval, count, bytes);
	//count = 0;
	//bytes = 0;
	for (j = 0; j < filter_count; j++)
		filters[j].count = filters[j].bytes = 0;
	(last_ts)++;
	
	if (trace_is_err(trace))
		trace_perror(trace,"%s",uri);

        trace_destroy(trace);

	if (!merge_inputs)
		output_destroy(output);
       
}
// TODO Decide what to do with -c option
static void usage(char *argv0)
{
	fprintf(stderr,"Usage:\n"
	"%s flags libtraceuri [libtraceuri...]\n"
       	"-i --interval=seconds	Duration of reporting interval in seconds\n"
	"-c --count=packets	Exit after count packets received\n"
	"-o --output-format=txt|csv|html|png Reporting output format\n"
	"-f --filter=bpf	Apply BPF filter. Can be specified multiple times\n"
	"-m --merge-inputs	Do not create separate outputs for each input trace\n"
	"-H --libtrace-help	Print libtrace runtime documentation\n"
	,argv0);
}

int main(int argc, char *argv[]) {

	int i;
	
	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",		1, 0, 'f' },
			{ "interval",		1, 0, 'i' },
			{ "count",		1, 0, 'c' },
			{ "output-format",	1, 0, 'o' },
			{ "libtrace-help",	0, 0, 'H' },
			{ "merge-inputs",	0, 0, 'm' },
			{ NULL, 		0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "c:f:i:o:Hm",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 'f': 
				++filter_count;
				filters=realloc(filters,filter_count*sizeof(struct filter_t));
				filters[filter_count-1].expr=strdup(optarg);
				filters[filter_count-1].filter=trace_create_filter(optarg);
				filters[filter_count-1].count=0;
				filters[filter_count-1].bytes=0;
				break;
			case 'i':
				packet_interval=atof(optarg);
				break;
			case 'c':
				packet_count=atoi(optarg);
				break;
			case 'o':
				if (output_format) free(output_format);
				output_format=strdup(optarg);
				break;
			case 'm':
				merge_inputs = 1;
				break;
			case 'H': 
				  trace_help(); 
				  exit(1); 
				  break;	
			default:
				fprintf(stderr,"Unknown option: %c\n",c);
				usage(argv[0]);
				return 1;
		}
	}

	if (packet_count == UINT64_MAX && packet_interval == UINT32_MAX) {
		packet_interval = 300; /* every 5 minutes */
	}

	if (optind >= argc)
		return 0;

	if (output_format)
		fprintf(stderr,"output format: '%s'\n",output_format);
	else
		fprintf(stderr,"output format: '%s'\n", DEFAULT_OUTPUT_FMT);
	
	
	if (merge_inputs) {
		/* If we're merging the inputs, we only want to create all
		 * the column headers etc. once rather than doing them once
		 * per trace */

		/* This is going to "name" the output based on the first 
		 * provided URI - admittedly not ideal */
		create_output(argv[optind]);
		if (output == NULL)
			return 0;
	}
		
	for(i=optind;i<argc;++i) {
		run_trace(argv[i]);
	}

	if (merge_inputs) {
		/* Clean up after ourselves */
		output_destroy(output);
	}


	return 0;
}
