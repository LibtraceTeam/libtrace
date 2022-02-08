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
#include <sys/types.h>
#ifndef WIN32
#        include <arpa/inet.h>
#        include <netinet/in.h>
#        include <netinet/in_systm.h>
#        include <netinet/ip.h>
#        include <netinet/ip_icmp.h>
#        include <netinet/tcp.h>
#        include <sys/socket.h>
#        include <sys/time.h>
#endif
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dagformat.h"
#include "data-struct/vector.h"
#include "libtrace_parallel.h"

static int expected = 100; // The number of packets we expect
static int timeout = 0;

void iferr(libtrace_t *trace, const char *msg)
{
        libtrace_err_t err = trace_get_err(trace);
        if (err.err_num == 0)
                return;
        printf("Error: %s: %s\n", msg, err.problem);
        exit(-err.err_num);
}

const char *lookup_uri(const char *type) {
        if (strchr(type, ':'))
                return type;
        if (!strcmp(type, "erf"))
                return "erf:traces/100_packets.erf";
        if (!strcmp(type, "erfprov"))
                return "erf:traces/provenance.erf";
        if (!strcmp(type, "rawerf"))
                return "rawerf:traces/100_packets.erf";
        if (!strcmp(type, "pcap"))
                return "pcap:traces/100_packets.pcap";
        if (!strcmp(type, "pcapng"))
                return "pcap:traces/100_packets.pcapng";
        if (!strcmp(type, "wtf"))
                return "wtf:traces/wed.wtf";
        if (!strcmp(type, "rtclient"))
                return "rtclient:chasm";
        if (!strcmp(type, "pcapfile"))
                return "pcapfile:traces/100_packets.pcap";
        if (!strcmp(type, "pcapfilens"))
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
        bool seen_resuming_message;
        bool seen_pausing_message;
        int count;
};

struct final {
        int threads;
        int packets;
};

static void *report_start(libtrace_t *trace UNUSED, libtrace_thread_t *t UNUSED,
                          void *global)
{
        uint32_t *magic = (uint32_t *)global;
        struct final *threadcounter =
            (struct final *)malloc(sizeof(struct final));

        assert(*magic == 0xabcdef);

        threadcounter->threads = 0;
        threadcounter->packets = 0;
        return threadcounter;
}

static void report_cb(libtrace_t *trace UNUSED,
                      libtrace_thread_t *sender UNUSED, void *global, void *tls,
                      libtrace_result_t *res)
{

        uint32_t *magic = (uint32_t *)global;
        struct final *threadcounter = (struct final *)tls;

        assert(*magic == 0xabcdef);
        assert(res->key == 0);

        threadcounter->threads++;
        threadcounter->packets += res->value.sint;
        printf("%d\n", res->value.sint);
}

static void report_end(libtrace_t *trace, libtrace_thread_t *t UNUSED,
                       void *global, void *tls)
{

        uint32_t *magic = (uint32_t *)global;
        struct final *threadcounter = (struct final *)tls;

        assert(*magic == 0xabcdef);
        assert(threadcounter->threads == trace_get_perpkt_threads(trace));
        assert(threadcounter->packets == expected);

        free(threadcounter);
}

static libtrace_packet_t *per_packet(libtrace_t *trace UNUSED,
                                     libtrace_thread_t *t UNUSED, void *global,
                                     void *tls, libtrace_packet_t *packet)
{
        struct TLS *storage = (struct TLS *)tls;
        uint32_t *magic = (uint32_t *)global;
        static __thread int count = 0;
        int a, *b, c = 0;

        assert(storage != NULL);
        assert(!storage->seen_stop_message);

        if (storage->seen_pausing_message)
                assert(storage->seen_resuming_message);

        assert(*magic == 0xabcdef);

        if (storage->count == 0)
                usleep(100000);
        storage->count++;
        count++;
        if (count == 1 && timeout) {
                alarm(timeout);
        }

        assert(count == storage->count);

        if (count > 100) {
                fprintf(stderr,
                        "Too many packets -- someone should stop me!\n");
                kill(getpid(), SIGTERM);
        }

        // Do some work to even out the load on cores
        b = &c;
        for (a = 0; a < 10000000; a++) {
                c += a * *b;
        }

        return packet;
}

static void *start_processing(libtrace_t *trace, libtrace_thread_t *t UNUSED,
                              void *global)
{

        static __thread bool seen_start_message = false;
        uint32_t *magic = (uint32_t *)global;
        struct TLS *storage = NULL;
        assert(*magic == 0xabcdef);

        assert(!seen_start_message);
        assert(trace);

        storage = (struct TLS *)malloc(sizeof(struct TLS));
        storage->seen_start_message = true;
        storage->seen_stop_message = false;
        storage->seen_resuming_message = false;
        storage->seen_pausing_message = false;
        storage->count = 0;

        seen_start_message = true;

        return storage;
}

static void stop_processing(libtrace_t *trace, libtrace_thread_t *t,
                            void *global, void *tls)
{

        static __thread bool seen_stop_message = false;
        struct TLS *storage = (struct TLS *)tls;
        uint32_t *magic = (uint32_t *)global;

        assert(storage != NULL);
        assert(!storage->seen_stop_message);
        assert(!seen_stop_message);
        assert(storage->seen_start_message);
        assert(*magic == 0xabcdef);

        seen_stop_message = true;
        storage->seen_stop_message = true;

        trace_publish_result(trace, t, (uint64_t)0,
                             (libtrace_generic_t){.sint = storage->count},
                             RESULT_USER);
        trace_post_reporter(trace);
        free(storage);
}

static void process_tick(libtrace_t *trace UNUSED, libtrace_thread_t *t UNUSED,
                         void *global UNUSED, void *tls UNUSED,
                         uint64_t tick UNUSED)
{

        fprintf(stderr, "Not expecting a tick packet\n");
        kill(getpid(), SIGTERM);
}

static void pause_processing(libtrace_t *trace UNUSED,
                             libtrace_thread_t *t UNUSED, void *global,
                             void *tls)
{

        static __thread bool seen_pause_message = false;
        struct TLS *storage = (struct TLS *)tls;
        uint32_t *magic = (uint32_t *)global;

        assert(storage != NULL);
        assert(!storage->seen_stop_message);
        assert(storage->seen_start_message);
        assert(*magic == 0xabcdef);

        assert(seen_pause_message == storage->seen_pausing_message);

        seen_pause_message = true;
        storage->seen_pausing_message = true;
}

static void resume_processing(libtrace_t *trace UNUSED,
                              libtrace_thread_t *t UNUSED, void *global,
                              void *tls)
{

        static __thread bool seen_resume_message = false;
        struct TLS *storage = (struct TLS *)tls;
        uint32_t *magic = (uint32_t *)global;

        assert(storage != NULL);
        assert(!storage->seen_stop_message);
        assert(storage->seen_start_message);
        assert(*magic == 0xabcdef);

        assert(seen_resume_message == storage->seen_resuming_message);

        seen_resume_message = true;
        storage->seen_resuming_message = true;
}

static libtrace_t *trace = NULL;
static void stop(int signal UNUSED)
{
        if (trace)
                trace_pstop(trace);
}

static int parse_int_or_exit(char *arg, char *argmsg, int min, int max)
{
        char *end = NULL;
        int ret;
        errno = 0;
        ret = strtol(arg, &end, 0);
        if (errno || '\0' != *end || ret <= min || ret > max) {
                fprintf(stderr, "Cannot parse argument '%s' as an integer.\n",
                        argmsg);
                exit(1);
        }
        return ret;
}

int main(int argc, char *argv[]) {
        int error = 0;
        const char *tracename;
        libtrace_callback_set_t *processing = NULL;
        libtrace_callback_set_t *reporter = NULL;
        uint32_t global = 0xabcdef;
        struct sigaction sigact;
        bool pause = 1;
        int opt;
        char *read = NULL;

        while ((opt = getopt(argc, argv, "pr:c:t:")) != -1) {
                switch (opt) {
                case 'p':
                        pause = 0;
                        break;
                case 'r':
                        read = optarg;
                        break;
                case 'c':
                        expected =
                            parse_int_or_exit(optarg, "count", 0, INT_MAX);
                        break;
                case 't':
                        timeout =
                            parse_int_or_exit(optarg, "timeout", -1, INT_MAX);
                        break;
                }
        }

        sigact.sa_handler = stop;
        sigemptyset(&sigact.sa_mask);
        sigact.sa_flags = SA_RESTART;
        sigaction(SIGINT, &sigact, NULL);
        sigaction(SIGALRM, &sigact, NULL);

        tracename = lookup_uri(read);

        trace = trace_create(tracename);
        iferr(trace, tracename);

        processing = trace_create_callback_set();
        trace_set_starting_cb(processing, start_processing);
        trace_set_stopping_cb(processing, stop_processing);
        trace_set_packet_cb(processing, per_packet);
        trace_set_pausing_cb(processing, pause_processing);
        trace_set_resuming_cb(processing, resume_processing);
        trace_set_tick_count_cb(processing, process_tick);
        trace_set_tick_interval_cb(processing, process_tick);

        reporter = trace_create_callback_set();
        trace_set_starting_cb(reporter, report_start);
        trace_set_stopping_cb(reporter, report_end);
        trace_set_result_cb(reporter, report_cb);

        trace_set_perpkt_threads(trace, 4);

        trace_pstart(trace, &global, processing, reporter);
        iferr(trace, tracename);

        /* Make sure traces survive a pause */
        if (pause) {
                trace_ppause(trace);
                iferr(trace, tracename);
                trace_pstart(trace, NULL, NULL, NULL);
                iferr(trace, tracename);
        }

        /* Wait for all threads to stop */
        trace_join(trace);

        global = 0xffffffff;

        /* Now check we have all received all the packets */
        if (error != 0) {
                iferr(trace, tracename);
        }

        trace_destroy(trace);
        trace_destroy_callback_set(processing);
        trace_destroy_callback_set(reporter);
        return error;
}
