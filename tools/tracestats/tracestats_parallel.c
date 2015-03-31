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

#include "libtrace_parallel.h"
#include "lt_inttypes.h"
#include <pthread.h>

struct libtrace_t *trace = NULL;

static void cleanup_signal(int signal UNUSED)
{
	if (trace)
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


static void* per_packet(libtrace_t *trace UNUSED, libtrace_thread_t *t UNUSED,
                        int mesg UNUSED, libtrace_generic_t data UNUSED,
                        libtrace_thread_t *sender UNUSED)
{
	return NULL;
}

static void report_result(libtrace_t *trace, int mesg,
                          libtrace_generic_t data,
                          libtrace_thread_t *sender UNUSED) {
	static uint64_t count=0, bytes=0;
	int i;
	libtrace_stat_t *stats;

	switch (mesg) {
	case MESSAGE_RESULT:
		/* Get the results from each core and sum 'em up */
		assert(data.res->key == 0);
		statistics_t * res = data.res->value.ptr;
		count += res[0].count;
		bytes += res[0].bytes;
		for (i = 0; i < filter_count; i++) {
			filters[i].count += res[i+1].count;
			filters[i].bytes += res[i+1].bytes;
		}
		free(res);
		break;
	case MESSAGE_STOPPING:
		/* We are done, print out results */
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


static void* fn_starting(libtrace_t *trace UNUSED, libtrace_thread_t *t,
                     libtrace_generic_t data UNUSED, void *global UNUSED, void*tls UNUSED) {
	/* Allocate space to hold a total count and one for each filter */
	statistics_t *results = calloc(1, sizeof(statistics_t) * (filter_count + 1));
	trace_set_tls(t, results);
	return NULL;
}


static void* fn_stopping(libtrace_t *trace, libtrace_thread_t *t UNUSED,
                     libtrace_generic_t data UNUSED, void *global UNUSED, void*tls) {
	statistics_t *results = tls;
	libtrace_generic_t gen;
	/* We only output one result per thread with the key 0 when the
	 * trace is over. */
	gen.ptr = results;
	trace_publish_result(trace, t, 0, gen, RESULT_USER);
	return NULL;
}

static void* fn_packet(libtrace_t *trace, libtrace_thread_t *t UNUSED,
                   libtrace_generic_t data, void *global UNUSED, void*tls) {
	statistics_t *results = tls;
	int i, wlen;

	/* Apply filters to every packet note the result */
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
			/* This is a race, but will be atomic */
			filters[i].filter = NULL;
		}
	}
	results[0].count++;
	results[0].bytes +=wlen;
	return data.pkt;
}

/* Process a trace, counting packets that match filter(s) */
static void run_trace(char *uri, char *config, char *config_file)
{

	fprintf(stderr,"%s:\n",uri);

	trace = trace_create(uri);

	if (trace_is_err(trace)) {
		trace_perror(trace,"Failed to create trace");
		return;
	}

	/* Apply config */
	if (config) {
		trace_set_configuration(trace, config);
	}

	if (config_file) {
		FILE * f = fopen(optarg, "r");
		if (f != NULL) {
			trace_set_configuration_file(trace, f);
			fclose(f);
		} else {
			perror("Failed to open configuration file\n");
			exit(-1);
		}
	}

	trace_set_handler(trace, MESSAGE_PACKET, fn_packet);
	trace_set_handler(trace, MESSAGE_STARTING, fn_starting);
	trace_set_handler(trace, MESSAGE_STOPPING, fn_stopping);

	/* Start the trace as a parallel trace */
	if (trace_pstart(trace, NULL, &per_packet, report_result)==-1) {
		trace_perror(trace,"Failed to start trace");
		return;
	}

	/* Wait for all threads to stop */
	trace_join(trace);

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
	char *config = NULL;
	char *config_file = NULL;

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
				config = optarg;
				break;
			case 'U':
				config_file = optarg;
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
		run_trace(argv[i], config, config_file);
	}
	if (optind+1<argc) {
		printf("Grand total:\n");
		printf("%30s:\t%12"PRIu64"\t%12" PRIu64 "\n","Total",totcount,totbytes);
	}
	
	return 0;
}
