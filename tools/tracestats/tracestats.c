/*
 *
 * Copyright (c) 2007-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
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

struct libtrace_t *inptrace = NULL;

static void cleanup_signal(int signal UNUSED)
{
	if (inptrace)
		trace_pstop(inptrace);
}

struct filter_t {
	char *expr;
	struct libtrace_filter_t *filter;
} *filters = NULL;

int filter_count=0;


typedef struct statistics {
	uint64_t count;
	uint64_t bytes;
} statistics_t;

volatile uint64_t totcount = 0;
volatile uint64_t totbytes = 0;


static void fn_result(libtrace_t *trace UNUSED,
                libtrace_thread_t *sender UNUSED,
                void *global UNUSED, void *tls,
                libtrace_result_t *result) {
	statistics_t *counters = (statistics_t *)tls;
	int i;

        assert(result->key == 0);
        statistics_t * res = result->value.ptr;
        counters[0].count += res[0].count;
        counters[0].bytes += res[0].bytes;

        for (i = 0; i < filter_count; i++) {
                counters[i+1].count += res[i+1].count;
                counters[i+1].bytes += res[i+1].bytes;
        }
        free(res);
}

static void fn_print_results(libtrace_t *trace, 
                libtrace_thread_t *sender UNUSED, void *global UNUSED,
                void *tls) {

	statistics_t *counters = (statistics_t *)tls;
        libtrace_stat_t *stats = NULL;
        int i;
        double pct;

        stats = trace_get_statistics(trace, NULL);
        printf("%-30s\t%12s\t%12s\t%7s\n","filter","count","bytes","% count");
        for(i=0;i<filter_count;++i) {
                if (counters[0].count == 0) {
                        pct = 0.0;
                } else {
                        pct = counters[i+1].count*100.0/counters[0].count;
                }
                printf("%30s:\t%12"PRIu64"\t%12"PRIu64"\t%7.03f\n",filters[i].expr,counters[i+1].count,counters[i+1].bytes,pct);
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
        printf("%30s:\t%12"PRIu64"\t%12" PRIu64 "\n","Total",counters[0].count,counters[0].bytes);
        totcount+=counters[0].count;
        totbytes+=counters[0].bytes;

}


static void* fn_starting(libtrace_t *trace UNUSED, libtrace_thread_t *t UNUSED, void *global UNUSED) {
	/* Allocate space to hold a total count and one for each filter */
	return calloc(1, sizeof(statistics_t) * (filter_count + 1));
}


static void fn_stopping(libtrace_t *trace, libtrace_thread_t *t UNUSED,
                        void *global UNUSED, void*tls) {
	statistics_t *results = (statistics_t *)tls;
	libtrace_generic_t gen;
	/* We only output one result per thread with the key 0 when the
	 * trace is over. */
	gen.ptr = results;
	trace_publish_result(trace, t, 0, gen, RESULT_USER);
}

static libtrace_packet_t* fn_packet(libtrace_t *trace,
                libtrace_thread_t *t UNUSED,
                void *global UNUSED, void*tls, libtrace_packet_t *pkt) {
	statistics_t *results = (statistics_t *)tls;
	int i, wlen;

        if (IS_LIBTRACE_META_PACKET(pkt))
                return pkt;

	/* Apply filters to every packet note the result */
	wlen = trace_get_wire_length(pkt);
        if (wlen == 0) {
                /* Don't count ERF provenance etc. */
                return pkt;
        }
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
			/* This is a race, but will be atomic */
			filters[i].filter = NULL;
		}
	}
	results[0].count++;
	results[0].bytes +=wlen;
	return pkt;
}

/* Process a trace, counting packets that match filter(s) */
static void run_trace(char *uri, int threadcount)
{

	fprintf(stderr,"%s:\n",uri);
        libtrace_callback_set_t *pktcbs, *rescbs;

	inptrace = trace_create(uri);

	if (trace_is_err(inptrace)) {
		trace_perror(inptrace,"Failed to create trace");
		return;
	}

        pktcbs = trace_create_callback_set();
        rescbs = trace_create_callback_set();

        trace_set_packet_cb(pktcbs, fn_packet);
        trace_set_starting_cb(pktcbs, fn_starting);
        trace_set_stopping_cb(pktcbs, fn_stopping);
        trace_set_starting_cb(rescbs, fn_starting);
        trace_set_result_cb(rescbs, fn_result);
        trace_set_stopping_cb(rescbs, fn_print_results);

        if (threadcount != 0)
                trace_set_perpkt_threads(inptrace, threadcount);

	/* Start the trace as a parallel trace */
	if (trace_pstart(inptrace, NULL, pktcbs, rescbs)==-1) {
		trace_perror(inptrace,"Failed to start trace");
		return;
	}

	/* Wait for all threads to stop */
	trace_join(inptrace);

	if (trace_is_err(inptrace))
		trace_perror(inptrace,"%s",uri);

	trace_destroy(inptrace);
        trace_destroy_callback_set(pktcbs);
        trace_destroy_callback_set(rescbs);
}

static void usage(char *argv0)
{
	fprintf(stderr,"Usage: %s [-h|--help] [--threads|-t threads] [--filter|-f bpf ]... libtraceuri...\n",argv0);
}

int main(int argc, char *argv[]) {

	int i;
	struct sigaction sigact;
        int threadcount = 1;

	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",	   1, 0, 'f' },
			{ "help", 0, 0, 'h' },
			{ "threads",		1, 0, 't' },
			{ NULL, 	   0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "f:ht:",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 'f':
				++filter_count;
				filters=realloc(filters,filter_count*sizeof(struct filter_t));
				filters[filter_count-1].expr=strdup(optarg);
				filters[filter_count-1].filter=trace_create_filter(optarg);
				break;
			case 'h':
			        usage(argv[0]);
                                return 1;
                        case 't':
                                threadcount = atoi(optarg);
                                if (threadcount <= 0)
                                        threadcount = 1;
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
		run_trace(argv[i], threadcount);
	}
	if (optind+1<argc) {
		printf("Grand total:\n");
		printf("%30s:\t%12"PRIu64"\t%12" PRIu64 "\n","Total",totcount,totbytes);
	}
	
	return 0;
}
