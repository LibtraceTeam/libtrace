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

#include "trace_vector.h"

#ifndef UINT32_MAX
	#define UINT32_MAX      0xffffffffU
#endif

#define DEFAULT_OUTPUT_FMT "txt"
#define TRACE_TIME 1

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


static int reduce(libtrace_t* trace, void* global_blob, uint64_t *last_ts)
{       
	int i,j;
	//uint64_t count=0, bytes=0;
	static uint64_t ts = 0;
	libtrace_vector_t results;
	libtrace_vector_init(&results, sizeof(libtrace_result_t));
	trace_get_results(trace, &results);
	//uint64_t packets;
	
	/* Get the results from each core and sum 'em up */
	for (i = 0 ; i < libtrace_vector_get_size(&results) ; i++) {
		libtrace_result_t result;
		
		assert(libtrace_vector_get(&results, i, (void *) &result) == 1);
		ts = libtrace_result_get_key(&result);
		if (*last_ts == 0)
			*last_ts = ts;
		
		result_t * res = libtrace_result_get_value(&result);
		static result_t *  last_res = NULL;
		assert(res != last_res);
		last_res = res;
		//printf("Mapper published %"PRIu64" - c=%"PRIu64"\n", ts, res->total.count);
		while (*last_ts < ts) {
			report_results((double) *last_ts * (double) packet_interval, count, bytes);
			count = 0;
			bytes = 0;
			for (j = 0; j < filter_count; j++)
				filters[j].count = filters[j].bytes = 0;
			(*last_ts)++;
		}
		
		count += res->total.count;
		bytes += res->total.bytes;
		for (j = 0; j < filter_count; j++) {
			filters[j].count += res->filters[j].count;
			filters[j].bytes += res->filters[j].bytes;
		}
		free(res);
	}
	// Done with these results - Free internally and externally
	libtrace_vector_destroy(&results);
	
	return 0;
}

typedef struct timestamp_sync {
	int64_t difference_usecs;
	uint64_t first_interval_number;
} timestamp_sync_t;


static int reduce_tracetime(libtrace_t* trace, void* global_blob, uint64_t *last_ts)
{
	int i,j;
	//uint64_t count=0, bytes=0;
	static uint64_t ts = 0;
	libtrace_vector_t results;
	libtrace_vector_init(&results, sizeof(libtrace_result_t));
	trace_get_results_check_temp(trace, &results, *last_ts);
	//trace_get_results(trace, &results);
	//uint64_t packets;
	
	/* Get the results from each core and sum 'em up */
	for (i = 0 ; i < libtrace_vector_get_size(&results) ; i++) {
		libtrace_result_t result;
		
		assert(libtrace_vector_get(&results, i, (void *) &result) == 1);
		ts = libtrace_result_get_key(&result);
		if (*last_ts == 0)
			*last_ts = ts;
		
		result_t * res = libtrace_result_get_value(&result);
		static result_t *  last_res = NULL;
		if (res == last_res) {
			printf("Hmm could be asserting but I'm not ;)\n");
		}
		//assert(res != last_res);
		last_res = res;
		//printf("Mapper published %"PRIu64" - c=%"PRIu64"\n", ts, res->total.count);
		/*while (*last_ts < ts) {
			report_results((double) *last_ts * (double) packet_interval, count, bytes);
			count = 0;
			bytes = 0;
			for (j = 0; j < filter_count; j++)
				filters[j].count = filters[j].bytes = 0;
			(*last_ts)++;
		}*/
		
		count += res->total.count;
		bytes += res->total.bytes;
		for (j = 0; j < filter_count; j++) {
			filters[j].count += res->filters[j].count;
			filters[j].bytes += res->filters[j].bytes;
		}
		free(res);
	}
	report_results((double) *last_ts * (double) packet_interval, count, bytes);
	count = 0;
	bytes = 0;
	for (j = 0; j < filter_count; j++)
		filters[j].count = filters[j].bytes = 0;
	(*last_ts)++;
	
	// Done with these results - Free internally and externally
	libtrace_vector_destroy(&results);
	
	return 0;
}

static void* per_packet(libtrace_t *trace, libtrace_packet_t *pkt, 
						libtrace_message_t *mesg,
						libtrace_thread_t *t)
{
	int i;
	static __thread uint64_t last_ts = 0, ts = 0;
	static __thread result_t * results = NULL;
	
	// Unsure when we would hit this case but the old code had it, I 
	// guess we should keep it
	if (pkt && trace_get_packet_buffer(pkt,NULL,NULL) == NULL) {
		
		ts = trace_get_seconds(pkt) / packet_interval;
		if (last_ts == 0)
			last_ts = ts;
		
		while (packet_interval != UINT64_MAX && last_ts<ts) {
			// Publish and make a new one new
			trace_publish_result(trace, (uint64_t) last_ts, results);
			trace_post_reduce(trace);
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
			case MESSAGE_STARTED:
				results = calloc(1, sizeof(result_t) + sizeof(statistic_t) * filter_count);
				break;
			case MESSAGE_STOPPED:
				if (results->total.count) {
					trace_publish_result(trace, (uint64_t) last_ts, results);
					trace_post_reduce(trace);
				}
		}
	}
	return pkt;
}
void * trace_retrive_inprogress_result(libtrace_t *libtrace, uint64_t key);
/**
 * A trace time version of map which will attempt to keep upto date 
 * with the incoming data and detect cases where results are missing and
 * recover correctly.
 */
static void* per_packet_tracetime(libtrace_t *trace, libtrace_packet_t *pkt, 
						libtrace_message_t *mesg,
						libtrace_thread_t *t)
{
	// Using first entry as total and those after for filter counts
	int i;
	static __thread uint64_t last_ts = 0, ts = 0;
	static __thread double debug_last = 0.0;
	static __thread result_t * tmp_result = NULL;
	
	if (pkt && trace_get_packet_buffer(pkt,NULL,NULL) != NULL) {
		ts = trace_get_seconds(pkt) / packet_interval;
		
		if (debug_last != 0.0 && debug_last > trace_get_seconds(pkt))
			printf("packets out of order bitch :(\n");
		debug_last = trace_get_seconds(pkt);
		if (last_ts == 0)
			last_ts = ts;
		
		/*
		while (packet_interval != UINT64_MAX && last_ts<ts) {
			// Publish and make new
			trace_publish_result(trace, (uint64_t) last_ts, results);
			results = malloc(sizeof(result_t) + sizeof(statistic_t) * filter_count);
			memset(results, 0, sizeof(result_t) + sizeof(statistic_t) * filter_count);
			last_ts++;
		}*/
		
		/* Calculate count for filters */
		for(i=0;i<filter_count;++i) {
			if(trace_apply_filter(filters[i].filter, pkt)) {
				tmp_result->filters[i].count = 1;
				tmp_result->filters[i].bytes = trace_get_wire_length(pkt);
			} else {
				tmp_result->filters[i].count = 0;
				tmp_result->filters[i].bytes = 0;
			}
		}
		
		/* Now Update the currently stored result */
		result_t * results = (result_t *) trace_retrive_inprogress_result(trace, ts);
		
		if (!results) {
			results = malloc(sizeof(result_t) + sizeof(statistic_t) * filter_count);
			memset(results, 0, sizeof(result_t) + sizeof(statistic_t) * filter_count);
		}
		assert(results);
		/* Now add to the current results */
		results->total.count++;
		results->total.bytes +=trace_get_wire_length(pkt);
		/* Now add on filters */
		for(i=0;i<filter_count;++i) {
			results->filters[i].count += tmp_result->filters[i].count;
			results->filters[i].bytes += tmp_result->filters[i].bytes;
		}
		/* Now release the lock and send it away place that back into the buffer */
		trace_update_inprogress_result(trace, ts, (void *) results);
		/*if (count >= packet_count) {
			report_results(ts,count,bytes);
			count=0;
			bytes=0;
		}*/ // Hmm what was happening here doesn't match up with any of the documentations!!!
	}
	if (mesg) {
		// printf ("%d.%06d READ #%"PRIu64"\n", tv.tv_sec, tv.tv_usec, trace_packet_get(packet));
		switch (mesg->code) {
			case MESSAGE_STARTED:
				tmp_result = calloc(1, sizeof(result_t) + sizeof(statistic_t) * filter_count);
				break;
			case MESSAGE_STOPPED:
				trace_retrive_inprogress_result(trace, 0);
				trace_update_inprogress_result(trace, 1, NULL);
		}
	}
	// Done push the final results
	/*if (results->total.count)
		trace_publish_result(trace, (uint64_t) last_ts, results);*/
	
	return pkt;
}

/* Process a trace, counting packets that match filter(s) */
static void run_trace(char *uri)
{
	int j;
	uint64_t last_ts = 0;

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
	trace_parallel_config(trace, TRACE_OPTION_TRACETIME, &i);
#if TRACE_TIME
	if (trace_pstart(trace, NULL, &per_packet_tracetime, NULL)==-1) {
#else
	if (trace_pstart(trace, NULL, &per_packet, NULL)==-1) {
#endif
		trace_perror(trace,"Failed to start trace");
		trace_destroy(trace);
		if (!merge_inputs)
			output_destroy(output);
		return;
	}

#if TRACE_TIME
	// First we wait for a message telling us that a timestamp has been 
	// published this allows us to approximately synchronize with the time
	libtrace_message_t message;
	int64_t offset;
	libtrace_packet_t *packet;
	struct timeval *tv, tv_real;
	
	
	do {
		// TODO Put a timeout here also
		libtrace_thread_get_message(trace, &message);
	} while (retrive_first_packet(trace, &packet, &tv) == 0);
	tv_real = trace_get_timeval(packet);
	offset = tv_to_usec(&tv_real) - tv_to_usec(tv);
	last_ts = trace_get_seconds(packet) / packet_interval;
	printf("Got first yay offset=%"PRId64" first_interval=%"PRIu64"\n", offset, last_ts);
	/*
	while (!got_first) {
		// Wait for a message indicating we've got our 'first' packet, note not a 100% guarantee its our first but pretty likely 
		
		
		
		assert(pthread_mutex_lock(&lock_more) == 0);
		
		for (i=0; i < 2; ++i) {
			if (initial_stamps[i].difference_usecs) { // Hmm certainly this cannot possibly lineup 100%??
				got_first=1;
				last_ts = initial_stamps[i].first_interval_number;
				offset = initial_stamps[i].difference_usecs;
				printf("Got first yay offset=%"PRId64" first_interval=%"PRIu64"\n", offset, last_ts);
			}
		}
		assert(pthread_mutex_unlock(&lock_more) == 0);
	}*/
	while (!trace_finished(trace)) {
		struct timeval tv;
		// Now try our best to read that one out
		
		// Read messages
		//libtrace_thread_get_message(trace, &message);
		
		// We just release and do work currently, maybe if something
		// interesting comes through we'd deal with that
		//libtrace_thread_get_message(trace, &message);
		
		//while (libtrace_thread_try_get_message(trace, &message) != LIBTRACE_MQ_FAILED) { }
		
		/* Now wait for a second after we should see the results */
		uint64_t next_update_time, t_usec;
		next_update_time = (last_ts*packet_interval + packet_interval + 1) * 1000000 + offset;
		gettimeofday(&tv, NULL);
		t_usec = tv.tv_sec;
		t_usec *= 1000000;
		t_usec += tv.tv_usec;
		
		//printf("Current time=%"PRIu64" Next result ready=%"PRIu64" =%f\n", t_usec, next_update_time, ((double) next_update_time - (double) t_usec) / 1000000.0);
		if (next_update_time > t_usec) {
			tv.tv_sec = (next_update_time - t_usec) / 1000000;
			tv.tv_usec = (next_update_time - t_usec) % 1000000;
			select(0, NULL, NULL, NULL, &tv);
		}
		reduce_tracetime(trace, NULL, &last_ts);
	}
#else
	// reduce
	while (!trace_finished(trace)) {
		// Read messages
		libtrace_message_t message;
		
		// We just release and do work currently, maybe if something
		// interesting comes through we'd deal with that
		libtrace_thread_get_message(trace, &message);
		
		while (libtrace_thread_try_get_message(trace, &message) != LIBTRACE_MQ_FAILED) { }
		reduce(trace, NULL, &last_ts);
	}
#endif

	// Wait for all threads to stop
	trace_join(trace);
	
	reduce(trace, NULL, &last_ts);
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
