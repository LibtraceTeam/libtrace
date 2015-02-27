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
#include "data-struct/vector.h"
#include "data-struct/message_queue.h"
#include "combiners.h"
#include <pthread.h>

struct libtrace_t *trace = NULL;

static void cleanup_signal(int signal)
{
	static int s = 0;
	(void)signal;
	// trace_interrupt();
	// trace_pstop isn't really signal safe because its got lots of locks in it
    trace_pstop(trace);
    /*if (s == 0) {
		if (trace_ppause(trace) == -1)
			trace_perror(trace, "Pause failed");
	}
	else {
		if (trace_pstart(trace, NULL, NULL, NULL) == -1)
			trace_perror(trace, "Start failed");
    }*/
	s = !s;
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


//libtrace_message_t mesg
static void* per_packet(libtrace_t *trace, libtrace_thread_t *t,
                        int mesg, libtrace_generic_t data,
                        libtrace_thread_t *sender)
{
	// Using first entry as total and those after for filter counts
	static __thread statistics_t * results = NULL;
	int i, wlen;
	libtrace_stat_t *stats;


	// printf ("%d.%06d READ #%"PRIu64"\n", tv.tv_sec, tv.tv_usec, trace_packet_get(packet));
	switch (mesg) {
	case MESSAGE_PACKET:
		wlen = trace_get_wire_length(data.pkt);
		for(i=0;i<filter_count;++i) {
			if (filters[i].filter == NULL)
				continue;
			if(trace_apply_filter(filters[i].filter,data.pkt) > 0) {
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
		return data.pkt;
	case MESSAGE_STOPPING:
		stats = trace_create_statistics();
		trace_get_thread_statistics(trace, t, stats);
		trace_print_statistics(stats, stderr, NULL);
		free(stats);
		trace_publish_result(trace, t, 0, (libtrace_generic_t){.ptr = results}, RESULT_NORMAL); // Only ever using a single key 0
		//fprintf(stderr, "tracestats_parallel:\t Stopping thread - publishing results\n");
		break;
	case MESSAGE_STARTING:
		results = calloc(1, sizeof(statistics_t) * (filter_count + 1));
		break;
	case MESSAGE_DO_PAUSE:
		assert(!"GOT Asked to pause!!!\n");
		break;
	case MESSAGE_PAUSING:
		//fprintf(stderr, "tracestats_parallel:\t pausing thread\n");
		break;
	case MESSAGE_RESUMING:
		//fprintf(stderr, "tracestats_parallel:\t resuming thread\n");
		break;
	}
	return NULL;
}

static void report_result(libtrace_t *trace UNUSED, libtrace_result_t *result, libtrace_message_t *mesg) {
	static uint64_t count=0, bytes=0;
	uint64_t packets;
	int i;
	if (result) {
		int j;
		/* Get the results from each core and sum 'em up */
		assert(libtrace_result_get_key(result) == 0);
		statistics_t * res = libtrace_result_get_value(result).ptr;
		count += res[0].count;
		bytes += res[0].bytes;
		for (j = 0; j < filter_count; j++) {
			filters[j].count += res[j+1].count;
			filters[j].bytes += res[j+1].bytes;
		}
		free(res);
	} else switch (mesg->code) {
		libtrace_stat_t *stats;
		case MESSAGE_STOPPING:
			stats = trace_get_statistics(trace, NULL);
			printf("%-30s\t%12s\t%12s\t%7s\n","filter","count","bytes","%");
			for(i=0;i<filter_count;++i) {
				printf("%30s:\t%12"PRIu64"\t%12"PRIu64"\t%7.03f\n",filters[i].expr,filters[i].count,filters[i].bytes,filters[i].count*100.0/count);
				filters[i].bytes=0;
				filters[i].count=0;
			}
			if (stats->received_valid)
				fprintf(stderr,"%30s:\t%12" PRIu64"\n",
						"Input packets", stats->received);
			if (stats->filtered_valid)
				fprintf(stderr,"%30s:\t%12" PRIu64"\n",
						"Filtered packets", stats->filtered);
			if (stats->dropped_valid)
				fprintf(stderr,"%30s:\t%12" PRIu64"\n",
						"Dropped packets",stats->dropped);
			if (stats->accepted_valid)
				fprintf(stderr,"%30s:\t%12" PRIu64 "\n",
						"Accepted packets", stats->accepted);
			if (stats->errors_valid)
				fprintf(stderr,"%30s:\t%12" PRIu64 "\n",
						"Erred packets", stats->errors);
			printf("%30s:\t%12"PRIu64"\t%12" PRIu64 "\n","Total",count,bytes);
			totcount+=count;
			totbytes+=bytes;
	}
}

static uint64_t rand_hash(libtrace_packet_t * pkt, void *data) {
	return rand();
}

static uint64_t bad_hash(libtrace_packet_t * pkt, void *data) {
	return 0;
}

struct user_configuration uc;


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
    //trace_set_hasher(trace, HASHER_CUSTOM, &rand_hash, NULL);
	//trace_parallel_config(trace, TRACE_OPTION_SET_PERPKT_THREAD_COUNT, &option);
	trace_parallel_config(trace, TRACE_OPTION_SET_CONFIG, &uc);
	trace_set_combiner(trace, &combiner_ordered, (libtrace_generic_types_t){0});

	//trace_parallel_config(trace, TRACE_OPTION_SET_MAPPER_BUFFER_SIZE, &option);

	/* OPTIONALLY SETUP CORES HERE BUT WE DON'T CARE ABOUT THAT YET XXX */

	/*if (trace_start(trace)==-1) {
	trace_perror(trace,"Failed to start trace");
	return;
	}*/
	global_blob_t blob;


	if (trace_pstart(trace, (void *)&blob, &per_packet, report_result)==-1) {
		trace_perror(trace,"Failed to start trace");
		return;
	}

	// Wait for all threads to stop
	trace_join(trace);

	//map_pair_iterator_t * results = NULL;
	//trace_get_results(trace, &results);

	//if (results != NULL) {
	//      reduce(trace, global_blob, results);
	//}
	if (trace_is_err(trace))
		trace_perror(trace,"%s",uri);

	trace_destroy(trace);
}

static void usage(char *argv0)
{
	fprintf(stderr,"Usage: %s [-H|--libtrace-help] [--filter|-f bpf ]... libtraceuri...\n",argv0);
}

int main(int argc, char *argv[]) {

	int i;
	struct sigaction sigact;
	ZERO_USER_CONFIG(uc);
	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",	   1, 0, 'f' },
			{ "libtrace-help", 0, 0, 'H' },
			{ "config",		1, 0, 'u' },
			{ "config-file",		1, 0, 'U' },
			{ NULL, 	   0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "f:Hu:U:",
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
			case 'u':
				  parse_user_config(&uc, optarg);
				  break;
			case 'U':;
				FILE * f = fopen(optarg, "r");
				if (f != NULL) {
					parse_user_config_file(&uc, f);
				} else {
					perror("Failed to open configuration file\n");
					usage(argv[0]);
				}
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
