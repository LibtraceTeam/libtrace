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
#include <signal.h>

#include <lt_inttypes.h>
#include "libtrace_parallel.h"
#include "output.h"
#include "rt_protocol.h"
#include "dagformat.h"

#ifndef UINT32_MAX
	#define UINT32_MAX      0xffffffffU
#endif

#define DEFAULT_OUTPUT_FMT "txt"

char *output_format=NULL;
int merge_inputs = 0;
int threadcount = 4;
int filter_count=0;
int burstsize=10;
uint8_t report_drops = 0;

struct filter_t {
	char *expr;
	struct libtrace_filter_t *filter;
	uint64_t count;
	uint64_t bytes;
} *filters = NULL;

uint64_t packet_count=UINT64_MAX;
double packet_interval=UINT32_MAX;

struct output_data_t *output = NULL;

uint64_t totalcount;
uint64_t totalbytes;

struct libtrace_t *currenttrace;

static void cleanup_signal(int signal UNUSED) {
        if (currenttrace) {
                trace_pstop(currenttrace);
        }
}

static void report_results(double ts,uint64_t count,uint64_t bytes,
                libtrace_stat_t *stats)
{
	int i=0, offset = 3;
	output_set_data_time(output,0,ts);
	output_set_data_int(output,1,count);
	output_set_data_int(output,2,bytes);
        if (stats) {
                if (stats->dropped_valid) {
                        output_set_data_int(output, 3, stats->dropped);
                } else {
                        output_set_data_int(output, 3, -1);
                }
                if (stats->missing_valid) {
                        output_set_data_int(output, 4, stats->missing);
                } else {
                        output_set_data_int(output, 4, -1);
                }
                offset += 2;
        }
	for(i=0;i<filter_count;++i) {
		output_set_data_int(output,i*2+offset,filters[i].count);
		output_set_data_int(output,i*2+offset+1,filters[i].bytes);
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
        if (report_drops) {
                output_add_column(output, "dropped");
                output_add_column(output, "missing");
        }
	for(i=0;i<filter_count;++i) {
		char buff[1024];
		snprintf(buff,sizeof(buff),"%s packets",filters[i].expr);
		output_add_column(output,buff);
		snprintf(buff,sizeof(buff),"%s bytes",filters[i].expr);
		output_add_column(output,buff);
	}
	output_flush_headings(output);

}

typedef struct statistic {
	uint64_t count;
	uint64_t bytes;
} statistic_t;

typedef struct result {
	struct statistic total;
	struct statistic filters[0];
} result_t;

static uint64_t glob_last_ts = 0;
static void cb_result(libtrace_t *trace, libtrace_thread_t *sender UNUSED,
                void *global UNUSED, void *tls UNUSED,
                libtrace_result_t *result) {
	uint64_t ts = 0;
        static bool stopped = false;
        static uint64_t packets_seen = 0;
	int j;
	result_t *res;
        libtrace_stat_t *stats = NULL;

        if (stopped)
                return;

        ts = result->key;
        res = result->value.ptr;
        if (glob_last_ts == 0)
                glob_last_ts = ts;
        if (report_drops) {
                stats = trace_create_statistics();
                trace_get_statistics(trace, stats);
        }
        while ((glob_last_ts >> 32) < (ts >> 32)) {
                report_results(glob_last_ts >> 32, totalcount, totalbytes,
                                stats);
                totalcount = 0;
                totalbytes = 0;
                for (j = 0; j < filter_count; j++)
                        filters[j].count = filters[j].bytes = 0;
                glob_last_ts = ts;
        }
        totalcount += res->total.count;
        packets_seen += res->total.count;
        totalbytes += res->total.bytes;
        for (j = 0; j < filter_count; j++) {
                filters[j].count += res->filters[j].count;
                filters[j].bytes += res->filters[j].bytes;
        }
        free(res);
        if (stats) {
                free(stats);
        }

        /* Be careful to only call pstop once from within this thread! */
        if (packets_seen > packet_count) {
                trace_pstop(trace);
                stopped = true;
        }
}

typedef struct threadlocal {
        result_t *results;
        uint64_t last_key;
} thread_data_t;

static void *cb_starting(libtrace_t *trace UNUSED,
        libtrace_thread_t *t UNUSED, void *global UNUSED)
{
        thread_data_t *td = calloc(1, sizeof(thread_data_t));
	td->results = calloc(1, sizeof(result_t) +
                        sizeof(statistic_t) * filter_count);
        return td;
}

static libtrace_packet_t *cb_packet(libtrace_t *trace, libtrace_thread_t *t,
                void *global UNUSED, void *tls, libtrace_packet_t *packet) {

        uint64_t key;
        thread_data_t *td = (thread_data_t *)tls;
        int i;
        size_t wlen;

        if (IS_LIBTRACE_META_PACKET(packet)) {
                return packet;
        }

        key = trace_get_erf_timestamp(packet);
        if ((key >> 32) >= (td->last_key >> 32) + packet_interval) {
                libtrace_generic_t tmp = {.ptr = td->results};
		trace_publish_result(trace, t, key,
                                tmp, RESULT_USER);
                trace_post_reporter(trace);
                td->last_key = key;
                td->results = calloc(1, sizeof(result_t) +
                                sizeof(statistic_t) * filter_count);
        }
        wlen = trace_get_wire_length(packet);
        if (wlen == 0) {
                /* Don't count ERF provenance and similar packets */
                return packet;
        }
        for(i=0;i<filter_count;++i) {
                if(trace_apply_filter(filters[i].filter, packet)) {
                        td->results->filters[i].count++;
                        td->results->filters[i].bytes+=wlen;
                }
        }

        td->results->total.count++;
        td->results->total.bytes += wlen;
        return packet;
}

static void cb_stopping(libtrace_t *trace, libtrace_thread_t *t,
                void *global UNUSED, void *tls) {

        thread_data_t *td = (thread_data_t *)tls;
        if (td->results->total.count) {
                libtrace_generic_t tmp = {.ptr = td->results};
                trace_publish_result(trace, t, td->last_key, tmp, RESULT_USER);
                trace_post_reporter(trace);
                td->results = NULL;
        }
}

static void cb_tick(libtrace_t *trace, libtrace_thread_t *t,
                void *global UNUSED, void *tls, uint64_t order) {

        thread_data_t *td = (thread_data_t *)tls;
        if (order > td->last_key) {
		libtrace_generic_t tmp = {.ptr = td->results};
                trace_publish_result(trace, t, order, tmp, RESULT_USER);
                trace_post_reporter(trace);
                td->last_key = order;
                td->results = calloc(1, sizeof(result_t) +
                                sizeof(statistic_t) * filter_count);
        }
}

/* Process a trace, counting packets that match filter(s) */
static void run_trace(char *uri)
{
        libtrace_t *trace = NULL;
	libtrace_callback_set_t *pktcbs, *repcbs;
        libtrace_stat_t *stats = NULL;

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
	trace_set_combiner(trace, &combiner_ordered, (libtrace_generic_t){0});
        trace_set_perpkt_threads(trace, threadcount);
	trace_set_burst_size(trace, burstsize);

	if (trace_get_information(trace)->live) {
                trace_set_tick_interval(trace, (int) (packet_interval * 1000));
	} else {
		trace_set_tracetime(trace, true);
	}

        pktcbs = trace_create_callback_set();
        trace_set_starting_cb(pktcbs, cb_starting);
        trace_set_stopping_cb(pktcbs, cb_stopping);
        trace_set_packet_cb(pktcbs, cb_packet);
        trace_set_tick_count_cb(pktcbs, cb_tick);
        trace_set_tick_interval_cb(pktcbs, cb_tick);

        repcbs = trace_create_callback_set();
        trace_set_result_cb(repcbs, cb_result);

        currenttrace = trace;
	if (trace_pstart(trace, NULL, pktcbs, repcbs)==-1) {
		trace_perror(trace,"Failed to start trace");
		trace_destroy(trace);
                trace_destroy_callback_set(pktcbs);
                trace_destroy_callback_set(repcbs);
		if (!merge_inputs)
			output_destroy(output);
		return;
	}


	// Wait for all threads to stop
	trace_join(trace);
	
	// Flush the last one out
        if (report_drops) {
                stats = trace_create_statistics();
                stats = trace_get_statistics(trace, stats);
        }
	report_results((glob_last_ts >> 32), totalcount, totalbytes, stats);
	if (trace_is_err(trace))
		trace_perror(trace,"%s",uri);

        if (stats) {
                free(stats);
        }
        trace_destroy(trace);
        trace_destroy_callback_set(pktcbs);
        trace_destroy_callback_set(repcbs);

	if (!merge_inputs)
		output_destroy(output);
       
}

// TODO Decide what to do with -c option
static void usage(char *argv0)
{
	fprintf(stderr,"Usage:\n"
	"%s flags libtraceuri [libtraceuri...]\n"
       	"-i --interval=seconds	Duration of reporting interval in seconds\n"
	"-c --count=packets	Exit after count packets have been processed\n"
	"-t --threads=max	Create 'max' processing threads (default: 4)\n"
	"-o --output-format=txt|csv|html|png Reporting output format\n"
	"-f --filter=bpf	Apply BPF filter. Can be specified multiple times\n"
	"-m --merge-inputs	Do not create separate outputs for each input trace\n"
	"-N --nobuffer		Disable packet buffering within libtrace to force faster\n"
	"			updates at very low traffic rates\n"
        "-d --report-drops      Include statistics about number of packets dropped or\n"
        "                       lost by the capture process\n"
	"-h --help	Print this usage statement\n"
	,argv0);
}

int main(int argc, char *argv[]) {

	int i;
        struct sigaction sigact;
	
	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",		1, 0, 'f' },
			{ "interval",		1, 0, 'i' },
			{ "count",		1, 0, 'c' },
			{ "output-format",	1, 0, 'o' },
			{ "help",	        0, 0, 'h' },
			{ "merge-inputs",	0, 0, 'm' },
			{ "threads",	        1, 0, 't' },
			{ "nobuffer",	        0, 0, 'N' },
			{ "report-drops",	0, 0, 'd' },
			{ NULL, 		0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "c:f:i:o:t:dhmN",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
                        case 'd':
                                report_drops = 1;
                                break;
			case 'N':
				burstsize = 1;
				break;
			case 'f': 
				++filter_count;
				filters=realloc(filters,filter_count*sizeof(struct filter_t));
				filters[filter_count-1].expr=strdup(optarg);
				filters[filter_count-1].filter=trace_create_filter(optarg);
				filters[filter_count-1].count=0;
				filters[filter_count-1].bytes=0;
				break;
                        case 't':
                                threadcount = atoi(optarg);
                                if (threadcount <= 0)
                                        threadcount = 1;
                                break;
			case 'i':
				packet_interval=atof(optarg);
				break;
			case 'c':
				packet_count=strtoul(optarg, NULL, 10);
				break;
			case 'o':
				if (output_format) free(output_format);
				output_format=strdup(optarg);
				break;
			case 'm':
				merge_inputs = 1;
				break;
			case 'h':
				  usage(argv[0]);
				  return 1;
			default:
				fprintf(stderr,"Unknown option: %c\n",c);
				usage(argv[0]);
				return 1;
		}
	}

	if (packet_count == UINT64_MAX && packet_interval == UINT32_MAX) {
		packet_interval = 60; /* every minute */
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
	
        sigact.sa_handler = cleanup_signal;
        sigemptyset(&sigact.sa_mask);
        sigact.sa_flags = SA_RESTART;

        sigaction(SIGINT, &sigact, NULL);
        sigaction(SIGTERM, &sigact, NULL);


	for(i=optind;i<argc;++i) {
		run_trace(argv[i]);
	}

	if (merge_inputs) {
		/* Clean up after ourselves */
		output_destroy(output);
	}


	return 0;
}
