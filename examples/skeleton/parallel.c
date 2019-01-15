/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007-2015 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson
 *          Perry Lorier
 *          Shane Alcock
 *          Richard Sanger
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

#include "libtrace_parallel.h"

volatile int done = 0;
libtrace_t *inptrace = NULL;

static void cleanup_signal(int sig) {
        (void)sig;      /* avoid warnings about unused parameter */
        done = 1;
        if (inptrace)
                trace_pstop(inptrace);
}


/* Thread local storage for the reporting thread */
struct rstorage {
        int replaceme;
};

/* Thread local storage for each processing thread */
struct pstorage {
        uint32_t replaceme;
};

static void *report_start(libtrace_t *trace,
                libtrace_thread_t *t,
                void *global) {

        /* Create any local storage required by the reporter thread and
         * return it. */
        struct rstorage *rs = (struct rstorage *)malloc(sizeof(struct rstorage));
        rs->replaceme = 0;

        assert(trace);
        assert(t);
        assert(global);

        return rs;
}

static void report_cb(libtrace_t *trace,
                libtrace_thread_t *sender,
                void *global, void *tls, libtrace_result_t *res) {

        struct rstorage *rs = (struct rstorage *)tls;
        assert(trace);
        assert(sender);
        assert(global);
        assert(rs);
        assert(res);

        /* Process the result */

        /* Make sure we free any packets included in the result */
        if (res->type == RESULT_PACKET)
                trace_free_packet(trace, res->value.pkt);
}

static void report_end(libtrace_t *trace, libtrace_thread_t *t,
                void *global, void *tls) {

        /* Free the local storage and print any final results */
        struct rstorage *rs = (struct rstorage *)tls;
        free(rs);
        assert(trace);
        assert(t);
        assert(global);
}

static libtrace_packet_t *per_packet(libtrace_t *trace,
                libtrace_thread_t *t,
                void *global, void *tls, libtrace_packet_t *packet) {
        struct pstorage *ps = (struct pstorage *)tls;
        assert(trace);
        assert(t);
        assert(global);
        assert(ps);
        /* Do something with the packet */

        /* In this example, we are just forwarding the packet to the reporter */
        trace_publish_result(trace, t, 0, (libtrace_generic_t){.pkt = packet}, RESULT_PACKET);
        return NULL;
}

static void *start_processing(libtrace_t *trace, libtrace_thread_t *t UNUSED,
                void *global) {

        /* Create any local storage required by the reporter thread and
         * return it. */
        struct pstorage *ps = (struct pstorage *)malloc(sizeof(struct pstorage));
        ps->replaceme = 0;

        assert(trace);
        assert(t);
        assert(global);
        return ps;
}

static void stop_processing(libtrace_t *trace, libtrace_thread_t *t,
                void *global, void *tls) {

        struct pstorage *ps = (struct pstorage *)tls;

        /* May want to do a final publish here... */

        assert(trace);
        assert(t);
        assert(global);
        free(ps);
}

static void process_tick(libtrace_t *trace, libtrace_thread_t *t,
                void *global, void *tls, uint64_t tick) {

        struct pstorage *ps = (struct pstorage *)tls;

        /* Publish or ignore the tick, as appropriate */
        assert(trace);
        assert(t);
        assert(global);
        assert(ps);

        if (tick) return;

}

static void pause_processing(libtrace_t *trace,
                libtrace_thread_t *t,
                void *global, void *tls) {

        struct pstorage *ps = (struct pstorage *)tls;
        assert(trace);
        assert(t);
        assert(global);
        assert(ps);

}

static void resume_processing(libtrace_t *trace,
                libtrace_thread_t *t,
                void *global, void *tls) {

        struct pstorage *ps = (struct pstorage *)tls;
        assert(trace);
        assert(t);
        assert(global);
        assert(ps);

}

static void custom_msg(libtrace_t *trace, libtrace_thread_t *t, void *global,
                void *tls, int mesg, libtrace_generic_t data,
                libtrace_thread_t *sender) {

        struct pstorage *ps = (struct pstorage *)tls;
        assert(trace);
        assert(t);
        assert(global);
        assert(ps);

        assert(mesg >= MESSAGE_USER);
        assert(sizeof(data) == 8);

        assert(sender || sender == NULL);
}

static void usage(char *prog) {
        fprintf(stderr, "Usage for %s\n\n", prog);
        fprintf(stderr, "%s [options] inputURI [inputURI ...]\n\n", prog);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "\t-t threads Set the number of processing threads\n");
        fprintf(stderr, "\t-f expr    Discard all packets that do not match the BPF expression\n");

        exit(0);
}

int main(int argc, char *argv[]) {
        libtrace_callback_set_t *processing = NULL;
        libtrace_callback_set_t *reporter = NULL;
        libtrace_filter_t *filter = NULL;
        char *filterstring = NULL;
        int i, opt, retcode=0;
        struct sigaction sigact;
        int threads = 4;

        /* TODO replace this with whatever global data your threads are
         * likely to need. */
        uint32_t global = 0;

	if (argc<2) {
                usage(argv[0]);
	}

        while ((opt = getopt(argc, argv, "f:t:")) != EOF) {
                switch (opt) {
                        case 'f':
                                filterstring = optarg;
                                break;
                        case 't':
                                threads = atoi(optarg);
                                break;
                        default:
                                usage(argv[0]);
                }
        }

        if (optind + 1 > argc) {
                usage(argv[0]);
                return 1;
        }

        if (filterstring) {
                filter = trace_create_filter(filterstring);
        }

        sigact.sa_handler = cleanup_signal;
        sigemptyset(&sigact.sa_mask);
        sigact.sa_flags = SA_RESTART;

        sigaction(SIGINT, &sigact, NULL);
        sigaction(SIGTERM, &sigact, NULL);

        processing = trace_create_callback_set();
        trace_set_starting_cb(processing, start_processing);
        trace_set_stopping_cb(processing, stop_processing);
        trace_set_packet_cb(processing, per_packet);
        trace_set_pausing_cb(processing, pause_processing);
        trace_set_resuming_cb(processing, resume_processing);
        trace_set_tick_count_cb(processing, process_tick);
        trace_set_tick_interval_cb(processing, process_tick);
        trace_set_user_message_cb(processing, custom_msg);

        reporter = trace_create_callback_set();
        trace_set_starting_cb(reporter, report_start);
        trace_set_stopping_cb(reporter, report_end);
        trace_set_result_cb(reporter, report_cb);

        for (i = optind; i < argc; i++) {

        	inptrace = trace_create(argv[i]);

                if (trace_is_err(inptrace)) {
                        trace_perror(inptrace, "Opening trace file");
                        retcode = -1;
                        break;
                }

                if (filter && trace_config(inptrace, TRACE_OPTION_FILTER, filter) == -1) {
                        trace_perror(inptrace, "trace_config(filter)");
                        retcode = -1;
                        break;
                }

                trace_set_perpkt_threads(inptrace, threads);
                trace_set_combiner(inptrace, &combiner_ordered,
                                (libtrace_generic_t) {0});
                trace_set_hasher(inptrace, HASHER_BIDIRECTIONAL, NULL, NULL);

        	if (trace_pstart(inptrace, &global, processing, reporter)) {
                        trace_perror(inptrace, "Starting trace");
                        break;
                }

        	/* Wait for all threads to stop */
	        trace_join(inptrace);

                if (trace_is_err(inptrace)) {
                        trace_perror(inptrace, "Processing packets");
                        retcode = -1;
                        break;
                }

                if (done)
                        break;
        }

        if (filter)
                trace_destroy_filter(filter);
        trace_destroy(inptrace);
        trace_destroy_callback_set(processing);
        trace_destroy_callback_set(reporter);
        return retcode;
}
