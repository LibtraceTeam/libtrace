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

/* 
 * This program takes a series of traces and bpf filters and outputs how many
 * bytes/packets
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
#include <signal.h>

#include "libtrace.h"
#include "lt_inttypes.h"
#include "trace_vector.h"
#include <pthread.h>

struct libtrace_t *trace;

static void cleanup_signal(int signal)
{
	(void)signal;
	//trace_interrupt();
	// trace_pstop isn't really signal safe because its got lots of locks in it
	trace_pstop(trace);
}

struct filter_t {
	char *expr;
	struct libtrace_filter_t *filter;
	uint64_t count;
	uint64_t bytes;
} *filters = NULL;
int filter_count=0;
volatile uint64_t totcount = 0;
volatile uint64_t totbytes = 0;


typedef struct global_blob {
	uint64_t * totcount;
	uint64_t * totbytes;
} global_blob_t;

typedef struct statistics {
	uint64_t count;
	uint64_t bytes;
} statistics_t;


static void* per_packet(libtrace_t *trace, libtrace_packet_t *pkt, libtrace_message_t *mesg, libtrace_thread_t *t)
{
	// Using first entry as total and those after for filter counts
	static __thread statistics_t * results = NULL;
	int i;
	
	if (pkt) {
		int wlen = trace_get_wire_length(pkt);
		for(i=0;i<filter_count;++i) {
			if (filters[i].filter == NULL)
				continue;
			if(trace_apply_filter(filters[i].filter,pkt) > 0) {
				results[i+1].count++;
				results[i+1].bytes+=wlen;
			}
			if (trace_is_err(trace)) {
				trace_perror(trace, "trace_apply_filter");
				fprintf(stderr, "Removing filter from filterlist\n");
				// XXX might be a problem across threads below
				filters[i].filter = NULL;
			}
		}
		results[0].count++;
		results[0].bytes +=wlen;
	}
	if (mesg) {
		// printf ("%d.%06d READ #%"PRIu64"\n", tv.tv_sec, tv.tv_usec, trace_packet_get(packet));
		switch (mesg->code) {
			case MESSAGE_STOPPED:
				trace_publish_result(trace, 0, results); // Only ever using a single key 0
				printf("Thread published resuslts WOWW \n");
				break;
			case MESSAGE_STARTED:
				results = calloc(1, sizeof(statistics_t) * (filter_count + 1));
				break;
			case MESSAGE_PAUSE:
				printf("GOT Asked to pause ahh\n");
				break;
		}
	}
	return pkt;
}

static int reduce(libtrace_t* trace, void* global_blob)
{
	int i,j;
	uint64_t count=0, bytes=0;
	libtrace_vector_t results;
	libtrace_vector_init(&results, sizeof(libtrace_result_t));
	trace_get_results(trace, &results);
	uint64_t packets;
	
	/* Get the results from each core and sum 'em up */
	for (i = 0 ; i < libtrace_vector_get_size(&results) ; i++) {
		libtrace_result_t result;
		assert(libtrace_vector_get(&results, i, (void *) &result) == 1);
		assert(libtrace_result_get_key(&result) == 0);
		statistics_t * res = libtrace_result_get_value(&result);
		count += res[0].count;
		bytes += res[0].bytes;
		for (j = 0; j < filter_count; j++) {
			filters[j].count += res[j+1].count;
			filters[j].bytes += res[j+1].bytes;
		}
		free(res);
	}
	// Done with these results - Free internally and externally
	libtrace_vector_destroy(&results);

    printf("%-30s\t%12s\t%12s\t%7s\n","filter","count","bytes","%");
	for(i=0;i<filter_count;++i) {
		printf("%30s:\t%12"PRIu64"\t%12"PRIu64"\t%7.03f\n",filters[i].expr,filters[i].count,filters[i].bytes,filters[i].count*100.0/count);
		filters[i].bytes=0;
		filters[i].count=0;
	}
	packets=trace_get_received_packets(trace);
	if (packets!=UINT64_MAX)
		fprintf(stderr,"%30s:\t%12" PRIu64"\n", 
				"Input packets", packets);
	packets=trace_get_filtered_packets(trace);
	if (packets!=UINT64_MAX)
		fprintf(stderr,"%30s:\t%12" PRIu64"\n", 
				"Filtered packets", packets);
	packets=trace_get_dropped_packets(trace);
	if (packets!=UINT64_MAX)
		fprintf(stderr,"%30s:\t%12" PRIu64"\n",
				"Dropped packets",packets);
	packets=trace_get_accepted_packets(trace);
	if (packets!=UINT64_MAX)
		fprintf(stderr,"%30s:\t%12" PRIu64 "\n",
				"Accepted Packets",packets);
	printf("%30s:\t%12"PRIu64"\t%12" PRIu64 "\n","Total",count,bytes);
	totcount+=count;
	totbytes+=bytes;
	
	return 0;
}

static uint64_t rand_hash(libtrace_packet_t * pkt) {
	return rand();
}

static uint64_t bad_hash(libtrace_packet_t * pkt) {
	return 0;
}

/* Process a trace, counting packets that match filter(s) */
static void run_trace(char *uri) 
{

	fprintf(stderr,"%s:\n",uri);

	trace = trace_create(uri);

	if (trace_is_err(trace)) {
		trace_perror(trace,"Failed to create trace");
		return;
	}
	
	int option = 2;
	//option = 10000;
	//trace_parallel_config(trace, TRACE_OPTION_USE_DEDICATED_HASHER, &option);
	//trace_parallel_config(trace, TRACE_OPTION_USE_SLIDING_WINDOW_BUFFER, &option);
	option = 2;
	trace_parallel_config(trace, TRACE_OPTION_SET_MAPPER_THREAD_COUNT, &option);
	//trace_parallel_config(trace, TRACE_OPTION_SET_MAPPER_BUFFER_SIZE, &option);

	/* OPTIONALLY SETUP CORES HERE BUT WE DON'T CARE ABOUT THAT YET XXX */

	/*if (trace_start(trace)==-1) {
	trace_perror(trace,"Failed to start trace");
	return;
	}*/
	global_blob_t blob;


	if (trace_pstart(trace, (void *)&blob, &per_packet, NULL)==-1) {
		trace_perror(trace,"Failed to start trace");
		return;
	}

	// Wait for all threads to stop
	trace_join(trace);
	reduce(trace, NULL);

	//map_pair_iterator_t * results = NULL;
	//trace_get_results(trace, &results);

	//if (results != NULL) {
	//      reduce(trace, global_blob, results);
	//}
	if (trace_is_err(trace))
		trace_perror(trace,"%s",uri);

	print_contention_stats(trace);
	trace_destroy(trace);
}

static void usage(char *argv0)
{
	fprintf(stderr,"Usage: %s [-H|--libtrace-help] [--filter|-f bpf ]... libtraceuri...\n",argv0);
}

int main(int argc, char *argv[]) {

	int i;
	struct sigaction sigact;

	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",	   1, 0, 'f' },
			{ "libtrace-help", 0, 0, 'H' },
			{ NULL, 	   0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "f:H",
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

	sigact.sa_handler = cleanup_signal;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = SA_RESTART;

	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);
	
	for(i=optind;i<argc;++i) {
		run_trace(argv[i]);
	}
	if (optind+1<argc) {
		printf("Grand total:\n");
		printf("%30s:\t%12"PRIu64"\t%12" PRIu64 "\n","Total",totcount,totbytes);
	}
	
	return 0;
}
