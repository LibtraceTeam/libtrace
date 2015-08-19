/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007 The University of Waikato, Hamilton, New Zealand.
 * Authors: Richard Sanger
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

#ifndef WIN32
#include <sys/time.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include "libtrace_parallel.h"

static double timeval_to_seconds(struct timeval tv) {
	return (double) tv.tv_sec + (double) tv.tv_usec / 1000000.0;
}

static void iferr(libtrace_t *trace,const char *msg)
{
	libtrace_err_t err = trace_get_err(trace);
	if (err.err_num==0)
		return;
	printf("Error: %s: %s\n", msg, err.problem);
	exit(1);
}

static bool check_range_jitter(double test, double target, double jit) {
	if ((test <= target + jit) && (test >= target - jit)) {
		return true;
	} else {
		printf("Have:%f Expected:%f (%f-%f)", test, target, target - jit, target + jit);
		return false;
	}
}


static int totalpkts = 0;
static int skippedpkts = 0;
static int expected;

libtrace_t *trace = NULL;
static void signal_handler(int signal)
{
	if (signal == SIGALRM) {
		trace_ppause(trace);

		/* check within 10 seconds we got 9-11 packets */
		assert(check_range_jitter(10.0, (double) totalpkts, 1.0));

		/* Now fullspeed it */
		trace_set_tracetime(trace, false);

		/* And restart */
		trace_pstart(trace, NULL, NULL, NULL);
	}
}

static void report_result(libtrace_t *trace UNUSED, int mesg,
                          libtrace_generic_t data,
                          libtrace_thread_t *sender UNUSED) {

	switch (mesg) {
	case MESSAGE_STARTING:
		break;
	case MESSAGE_RESULT:
		switch (data.res->type) {
		case RESULT_USER:
			totalpkts++;
			break;
		case RESULT_USER+1:
			skippedpkts++;
			break;
		}
		break;
	}
}

static void* per_packet(libtrace_t *trace, libtrace_thread_t *t,
                        int mesg, libtrace_generic_t data,
                        libtrace_thread_t *sender UNUSED) {
	struct timeval tv;
	double time;
	libtrace_message_t message;
	static __thread bool accepting = true;

	gettimeofday(&tv, NULL);
	time = timeval_to_seconds(tv);

	switch (mesg) {
	case MESSAGE_PACKET:
		/* In order to instantly pause a trace we don't delay any buffered packets
		 * These are sent after MESSAGE_PAUSING has been received */
		if (accepting) {
			fprintf(stderr, ".");
			trace_publish_result(trace, t, (uint64_t) time, (libtrace_generic_t){.rdouble = time}, RESULT_USER);

			/* Check that we are not blocking regular message delivery */
			message.code = MESSAGE_USER;
			message.sender = t;
			message.data.rdouble = time;
			trace_message_perpkts(trace, &message);
		} else {
			trace_publish_result(trace, t, (uint64_t) time, (libtrace_generic_t){.rdouble = time}, RESULT_USER+1);
		}
		return data.pkt;
	case MESSAGE_USER:
		assert (check_range_jitter(data.rdouble, time, 0.01));
		break;
	case MESSAGE_RESUMING:
		accepting = true;
		break;
	case MESSAGE_PAUSING:
		accepting = false;
		break;
	}
	return NULL;
}

/**
 * Test that tracetime playback functions.
 * Including:
 * * Delaying packets
 * * Not blocking messages
 * * Instantly returning when paused (or stopped)
 * * Can be switched off/on from a paused state
 */
int test_tracetime(const char *tracename) {
	int error = 0;
	struct timeval tv;
	double start, end;
	gettimeofday(&tv, NULL);
	start = timeval_to_seconds(tv);
	printf("Testing delay\n");

	// Create the trace
	trace = trace_create(tracename);
	iferr(trace,tracename);

	// Always use 2 threads for simplicity
	trace_set_perpkt_threads(trace, 2);
	trace_set_tracetime(trace, true);

	// Start it
	trace_pstart(trace, NULL, per_packet, report_result);
	iferr(trace,tracename);
	fprintf(stderr, "Running in tracetime (Will take about 10 seconds)\t");

	// Timeout after 10 which should be about 10 packets seconds
	alarm(10);

	/* Wait for all threads to stop */
	trace_join(trace);

	/* Now check we have all received all the packets */
	assert(skippedpkts <= 20); /* Note this is hard coded to the default burst_sizeX2 */
	if (error == 0) {
		if (totalpkts + skippedpkts == expected) {
			printf("success: %d packets read\n",expected);
		} else {
			printf("failure: %d packets expected, %d seen\n",expected,totalpkts);
			error = 1;
		}
	} else {
		iferr(trace,tracename);
	}
	/* The whole test should take about 10 seconds */
	gettimeofday(&tv, NULL);
	end = timeval_to_seconds(tv);
	assert(check_range_jitter(end-start, 10.0, 1.0));
	trace_destroy(trace);
	return error;
}

int main() {
	int error = 0;
	const char *tracename;
	expected = 100;

	signal(SIGALRM, signal_handler);

	tracename = "pcapfile:traces/100_seconds.pcap";

	error = test_tracetime(tracename);

	return error;
}
