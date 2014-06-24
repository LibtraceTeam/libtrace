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
 * $Id: test-rtclient.c,v 1.2 2006/02/27 03:41:12 perry Exp $
 *
 */
#ifndef WIN32
#  include <sys/time.h>
#  include <netinet/in.h>
#  include <netinet/in_systm.h>
#  include <netinet/tcp.h>
#  include <netinet/ip.h>
#  include <netinet/ip_icmp.h>
#  include <arpa/inet.h>
#  include <sys/socket.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "dagformat.h"
#include "libtrace.h"
#include "data-struct/vector.h"

void iferr(libtrace_t *trace,const char *msg)
{
	libtrace_err_t err = trace_get_err(trace);
	if (err.err_num==0)
		return;
	printf("Error: %s: %s\n", msg, err.problem);
	exit(1);
}

const char *lookup_uri(const char *type) {
	if (strchr(type,':'))
		return type;
	if (!strcmp(type,"erf"))
		return "erf:traces/100_packets.erf";
	if (!strcmp(type,"rawerf"))
		return "rawerf:traces/100_packets.erf";
	if (!strcmp(type,"pcap"))
		return "pcap:traces/100_packets.pcap";
	if (!strcmp(type,"wtf"))
		return "wtf:traces/wed.wtf";
	if (!strcmp(type,"rtclient"))
		return "rtclient:chasm";
	if (!strcmp(type,"pcapfile"))
		return "pcapfile:traces/100_packets.pcap";
	if (!strcmp(type,"pcapfilens"))
		return "pcapfile:traces/100_packetsns.pcap";
	if (!strcmp(type, "duck"))
		return "duck:traces/100_packets.duck";
	if (!strcmp(type, "legacyatm"))
		return "legacyatm:traces/legacyatm.gz";
	if (!strcmp(type, "legacypos"))
		return "legacypos:traces/legacypos.gz";
	if (!strcmp(type, "legacyeth"))
		return "legacyeth:traces/legacyeth.gz";
	if (!strcmp(type, "tsh"))
		return "tsh:traces/10_packets.tsh.gz";
	return type;
}


struct TLS {
	bool seen_start_message;
	bool seen_stop_message;
	bool seen_paused_message;
	bool seen_pausing_message;
	int count;
};
int x;

static void* per_packet(libtrace_t *trace, libtrace_packet_t *pkt, 
						libtrace_message_t *mesg,
						libtrace_thread_t *t) {
	struct TLS *tls;
	void* ret;
	tls = trace_get_tls(t);

	if (pkt) {
		int a,*b,c=0;
		assert(tls != NULL);
		assert(!(tls->seen_stop_message));
		tls->count++;
		if (tls->count>100) {
			fprintf(stderr, "Too many packets someone should stop me!!\n");
			kill(getpid(), SIGTERM);
		}
		// Do some work to even out the load on cores
		b = &c;
		for (a = 0; a < 10000000; a++) {
			c += a**b;
		}
		x = c;
	}
	else switch (mesg->code) {
		case MESSAGE_STARTED:
			assert(tls == NULL);
			tls = calloc(sizeof(struct TLS), 1);
			ret = trace_set_tls(t, tls);
			assert(ret == NULL);
			tls->seen_start_message = true;
			break;
		case MESSAGE_STOPPED:
			assert(tls->seen_start_message);
			assert(tls != NULL);
			tls->seen_stop_message = true;
			trace_set_tls(t, NULL);

			// All threads publish to verify the thread count
			trace_publish_result(trace, (uint64_t) 0, (void *) tls->count);
			trace_post_reduce(trace);
			free(tls);
			break;
		case MESSAGE_TICK:
			assert(tls->seen_start_message );
			fprintf(stderr, "Not expecting a tick packet\n");
			kill(getpid(), SIGTERM);
			break;
		case MESSAGE_PAUSING:
			assert(tls->seen_start_message);
			tls->seen_pausing_message = true;
			break;
		case MESSAGE_PAUSED:
			assert(tls->seen_pausing_message);
			tls->seen_paused_message = true;
			break;
	}
	return pkt;
}


/**
 * Test that the single threaded fallback works
 */
int test_100_threads(const char *tracename, int expected) {
	libtrace_t *trace;
	int error = 0;
	int count = 0;
	int i;
	printf("Testing single threaded\n");

	// Create the trace
	trace = trace_create(tracename);
	iferr(trace,tracename);

	// Enable the single threaded fallback codepath
	i = 100;
	trace_parallel_config(trace, TRACE_OPTION_SET_PERPKT_THREAD_COUNT, &i);

	// Start it
	trace_pstart(trace, NULL, per_packet, NULL);
	iferr(trace,tracename);

	/* Make sure traces survive a pause and restart */
	trace_ppause(trace);
	iferr(trace,tracename);
	trace_pstart(trace, NULL, NULL, NULL);
	iferr(trace,tracename);

	/* Wait for all threads to stop */
	trace_join(trace);
	libtrace_vector_t results;

	/* Now lets check the results */
	libtrace_vector_init(&results, sizeof(libtrace_result_t));
	trace_get_results(trace, &results);
	// Should have 100 results/threads here
	assert(libtrace_vector_get_size(&results) == 100);
	for (i = 0; i < libtrace_vector_get_size(&results); i++) {
		int ret;
		libtrace_result_t result;
		ret = libtrace_vector_get(&results, i, (void *) &result);
		assert(ret == 1);
		assert(libtrace_result_get_key(&result) == 0);
		count += (int) libtrace_result_get_value(&result);
		printf("%d,", (int) libtrace_result_get_value(&result));
	}
	printf(")\n");
	libtrace_vector_destroy(&results);

	if (error == 0) {
		if (count == expected) {
			printf("success: %d packets read\n",expected);
		} else {
			printf("failure: %d packets expected, %d seen\n",expected,count);
			error = 1;
		}
	} else {
		iferr(trace,tracename);
	}
    trace_destroy(trace);
    return error;
}

int main(int argc, char *argv[]) {
	int error = 0;
	int expected = 100;
	const char *tracename;

	if (argc<2) {
		fprintf(stderr,"usage: %s type\n",argv[0]);
		return 1;
	}

	tracename = lookup_uri(argv[1]);

	if (strcmp(argv[1],"rtclient")==0) expected=101;

	error = test_100_threads(tracename, expected);
    return error;
}