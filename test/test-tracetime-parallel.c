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


libtrace_t *trace = NULL;
int total = 0;

static void signal_handler(int signal)
{
	if (signal == SIGALRM) {
		trace_ppause(trace);

		/* check within 10 seconds we got 9-11 packets */
		assert(check_range_jitter(10.0, (double) total, 1.0));

		/* Now fullspeed it */
		trace_set_tracetime(trace, false);

		/* And restart */
		trace_pstart(trace, NULL, NULL, NULL);
	}
}

struct counter {
        int total;
        int skipped;
};

static void *start_report(libtrace_t *trace UNUSED,
                libtrace_thread_t *t UNUSED, void *global UNUSED) {
        
        struct counter *c = (struct counter *)malloc(sizeof(struct counter));
        c->total = 0;
        c->skipped = 0;
        return c;

}

static void stop_report(libtrace_t *trace UNUSED,
                libtrace_thread_t *t UNUSED, void *global UNUSED, void *tls) {

        struct counter *c = (struct counter *)tls;

        assert(c->skipped <= 20);
        assert(c->skipped + c->total == 100);

        free(c);
}

static void report_cb(libtrace_t *trace UNUSED,
                libtrace_thread_t *sender UNUSED, void *global UNUSED,
                void *tls, libtrace_result_t *result) {

        struct counter *c = (struct counter *)tls;
        if (result->type == RESULT_USER)
                c->total ++;
        if (result->type == RESULT_USER + 1)
                c->skipped ++;

        total = c->total;

}

static void *start_process(libtrace_t *trace UNUSED,
                libtrace_thread_t *t UNUSED, void *global UNUSED) {

        bool *accepting = (bool *)malloc(sizeof(bool));
        *accepting = true;
        return accepting;

}

static void stop_process(libtrace_t *trace UNUSED,
                libtrace_thread_t *t UNUSED, void *global UNUSED, void *tls) {
        bool *accepting = (bool *)tls;
        free(accepting);
}

static void pause_process(libtrace_t *trace UNUSED,
                libtrace_thread_t *t UNUSED, void *global UNUSED, void *tls) {
        bool *accepting = (bool *)tls;
        *accepting = false;
}

static void resume_process(libtrace_t *trace UNUSED,
                libtrace_thread_t *t UNUSED, void *global UNUSED, void *tls) {
        bool *accepting = (bool *)tls;
        *accepting = true;
}

static void user_message(libtrace_t *trace UNUSED,
                libtrace_thread_t *t UNUSED, void *global UNUSED,
                void *tls UNUSED, int msg UNUSED, libtrace_generic_t ts) {

	struct timeval tv;
	double time;

	gettimeofday(&tv, NULL);
	time = timeval_to_seconds(tv);

        assert(check_range_jitter(ts.rdouble, time, 0.01));
}

static libtrace_packet_t *per_packet(libtrace_t *trace, libtrace_thread_t *t,
                void *global UNUSED, void *tls, libtrace_packet_t *packet) {

	struct timeval tv;
	double time;
	libtrace_message_t message;
        bool *accepting = (bool *)tls;

	gettimeofday(&tv, NULL);
	time = timeval_to_seconds(tv);

        if (*accepting) {
                fprintf(stderr, ".");
                trace_publish_result(trace, t, (uint64_t)time,
                                (libtrace_generic_t){.rdouble = time},
                                RESULT_USER);
                /* Test that we are not interfering with message delivery */
                message.code = MESSAGE_USER;
                message.sender = t;
                message.data.rdouble = time;
                trace_message_perpkts(trace, &message);
        } else {
                trace_publish_result(trace, t, (uint64_t)time,
                                (libtrace_generic_t){.rdouble = time},
                                RESULT_USER+1);

        }
        return packet;

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
	libtrace_callback_set_t *processing;
        libtrace_callback_set_t *reporter;

        gettimeofday(&tv, NULL);
	start = timeval_to_seconds(tv);
	printf("Testing delay\n");

	// Create the trace
	trace = trace_create(tracename);
	iferr(trace,tracename);

	// Always use 2 threads for simplicity
	trace_set_perpkt_threads(trace, 2);
	trace_set_tracetime(trace, true);

        processing = trace_create_callback_set();
        trace_set_starting_cb(processing, start_process);
        trace_set_stopping_cb(processing, stop_process);
        trace_set_pausing_cb(processing, pause_process);
        trace_set_resuming_cb(processing, resume_process);
        trace_set_packet_cb(processing, per_packet);
        trace_set_user_message_cb(processing, user_message);

        reporter = trace_create_callback_set();
        trace_set_starting_cb(reporter, start_report);
        trace_set_stopping_cb(reporter, stop_report);
        trace_set_result_cb(reporter, report_cb);

        trace_set_reporter_thold(trace, 1);
	trace_set_burst_size(trace, 10);

	// Start it
	trace_pstart(trace, NULL, processing, reporter);
	iferr(trace,tracename);
	fprintf(stderr, "Running in tracetime (Will take about 10 seconds)\t");

	// Timeout after 10 which should be about 10 packets seconds
	alarm(10);

	/* Wait for all threads to stop */
	trace_join(trace);

	if (error != 0) {
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

	signal(SIGALRM, signal_handler);

	tracename = "pcapfile:traces/100_seconds.pcap";

	error = test_tracetime(tracename);
        fprintf(stderr, "\n");
	return error;
}
