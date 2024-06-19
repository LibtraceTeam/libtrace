/*
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
 */
/*
 * Test-hotplug is a parallel libtrace program to test opening, closing and
 * reopening traces within a single libtrace application.
 *
 * This testing tool starts and stops traces based on user input, either
 * starting or stopping traces following the order of the program arguments.
 *
 * I made this to test hotplug in DPDK was working correctly.
 *
 * For example, to test hotplug in DPDK is working:
 * ./test-hotplug pt=1,dpdkvdev:net_pcap0,iface=veth0 \
 *                pt=1,dpdkvdev:net_pcap1,iface=veth1
 *
 * Author: Richard Sanger
 */
#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include "libtrace_parallel.h"

#define MAX_TRACES 1024

typedef enum status {
    UNINITALISED,
    WAITING,
    RUNNING,
    STOPPED,
    JOINT,
    FAILED
} status_t;
typedef struct trace_info {
    libtrace_t *trace;
    status_t status;
    const char *uri;
    uint64_t pkts;
} trace_info_t;

volatile trace_info_t traces[MAX_TRACES] = {0};

/* The perpkt function, shared by all traces.
 * It simply counts packets against the trace they arrive on.
 */
static libtrace_packet_t *process_packet(libtrace_t *trace UNUSED,
                                         libtrace_thread_t *t UNUSED,
                                         void *global UNUSED, void *tls UNUSED,
                                         libtrace_packet_t *packet)
{
    trace_info_t *trace_inf = (trace_info_t *)global;
    trace_inf->pkts++;
    return packet;
}

libtrace_callback_set_t *pktcbs;

/* Stop all traces signal handler */
static void stop_all(int signal UNUSED) { trace_interrupt(); }

#define PRItrace "%s (%zu)"
#define printable(x) (x)->uri, ((x)-traces)

/* Stop only the oldest trace.
 * Not actually called from a signal handler */
static void stop_oldest(int signal UNUSED)
{
    static int stop_index = 0;

    if (stop_index >= MAX_TRACES) {
        fprintf(stderr, "No more to stop\n");
        return;
    }

    volatile trace_info_t *trace = &traces[stop_index];
    if (trace->status == RUNNING) {
        fprintf(stderr, "Stopping: " PRItrace "\n", printable(trace));
        trace_pstop(traces[stop_index].trace);
        fprintf(stderr, "Stopped: " PRItrace "\n", printable(trace));
        traces[stop_index].status = STOPPED;
        stop_index++;
    } else {
        fprintf(stderr, "Not stopping: " PRItrace " - it failed to start\n",
                printable(trace));
        stop_index++;
    }
}

/* Starts the next trace as per the command line arguments
 * Not actually called from a signal handler */
static void start_next(int signal UNUSED)
{
    static int start_index = 0;

    if (start_index >= MAX_TRACES ||
        traces[start_index].status == UNINITALISED) {
        fprintf(stderr, "No more traces to start\n");
        return;
    }
    volatile trace_info_t *trace = &traces[start_index];

    trace->trace = trace_create(trace->uri);
    if (trace_is_err(trace->trace)) {
        trace_perror(trace->trace, "ERROR opening trace file (" PRItrace ")",
                     printable(trace));
        trace_destroy(trace->trace);
        trace->trace = NULL;
        trace->status = FAILED;
        start_index++;
        return;
    }
    if (trace_pstart(trace->trace, (void *)trace, pktcbs, NULL)) {
        trace_perror(trace->trace, "ERROR starting trace (" PRItrace ")",
                     printable(trace));
        trace_destroy(trace->trace);
        trace->trace = NULL;
        trace->status = FAILED;
        start_index++;
        return;
    }
    fprintf(stderr, "Started trace " PRItrace "\n", printable(trace));
    trace->status = RUNNING;
    start_index++;
}

/* Print a brief status of all traces */
static void print_status_line()
{
    printf("Status: ");
    for (int i = 0; i < 1024; i++) {
        switch (traces[i].status) {
        case WAITING:
            printf("-");
            break;
        case STOPPED:
            printf("S");
            break;
        case FAILED:
            printf("!");
            break;
        case RUNNING:
            printf("R");
            break;
        case JOINT:
            printf("J");
            break;
        case UNINITALISED:
            break;
        }
    }
    printf("\n");
}

/* Print the full status of all traces */
static void print_full_status()
{
    for (int i = 0; i < 1024; i++) {
        volatile trace_info_t *trace = &traces[i];
        if (trace->status == UNINITALISED)
            continue;
        switch (trace->status) {
        case WAITING:
            printf("Trace " PRItrace " - Waiting (not yet started)",
                   printable(trace));
            break;
        case STOPPED:
            printf("Trace " PRItrace " - Stopped", printable(trace));
            break;
        case FAILED:
            printf("Trace " PRItrace " - Failed", printable(trace));
            break;
        case RUNNING:
            printf("Trace " PRItrace " - Running", printable(trace));
            break;
        case JOINT:
            printf("Trace " PRItrace " - Destroyed", printable(trace));
            break;
        case UNINITALISED:
            break;
        }
        printf(" - %" PRIu64 " packets read\n", trace->pkts);
    }
}

/* Wait for user input */
static void *wait_instruction(void *_arg UNUSED)
{

    printf("Type 's' to (s)tart a trace, 'e' to (e)nd a trace:\n");
    while (true) {
        int chr;
        print_status_line();
        do {
            switch (chr = getchar()) {
            case 's':
                start_next(0);
                break;
            case 'e':
                stop_oldest(0);
                break;
            case '?':
                printf("'s' to (s)tart a trace\n");
                printf("'e' to (e)nd a trace\n");
                printf("'p' to (p)rint trace status\n");
                break;
            case 'p':
                print_full_status();
            case '\n':
            case '\r':
                continue;
            case EOF:
                return NULL;
            default:
                printf("Unknown character: %d (type ? for help)\n", chr);
            }
            break;
        } while (1);
    }
    return NULL;
}

static void print_usage(const char *prog)
{
    fprintf(stderr, "usage: %s libtraceuri [libtraceuri2]\n", prog);
    fprintf(stderr,
            "An interactive program to test starting and stopping traces\n\n"
            "Traces are started and stopped in the order supplied.\n"
            "Type 's' the (s)tart the next format and 'e' the end the oldest\n"
            "This is primarily intended to test that a trace can open, close, "
            "and later\n"
            "reopen the same interface\n"
            "This program always starts by opening the first trace and exits "
            "when\n"
            "no formats are running, even if there are unopened formats.\n\n"
            "For example:\n"
            "%s pt=1,dpdkvdev:net_pcap0,iface=veth0 "
            "pt=1,dpdkvdev:net_pcap1,iface=veth1 "
            "pt=1,dpdkvdev:net_pcap0,iface=veth0\n"
            "With the sequence 'sesee'\n"
            "To test that DPDK can reopen the same interface (veth0) and have "
            "two\n"
            "running traces at the same time.",
            prog);
}

int main(int argc, char *argv[])
{
    pthread_t thread_id;

    /* Cleanup signal */
    struct sigaction sigact;
    sigact.sa_handler = stop_all;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sigact, NULL);

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        traces[i - 1].uri = argv[i];
        traces[i - 1].status = WAITING;
    }

    /* Create a callback set for our per packet threads */
    pktcbs = trace_create_callback_set();

    /* Set the packet callback to be our packet processing function */
    trace_set_packet_cb(pktcbs, process_packet);

    start_next(0);

    pthread_create(&thread_id, NULL, wait_instruction, NULL);

    /* Wait for the trace to finish */
    for (int i = 0; i < MAX_TRACES && traces[i].status != WAITING &&
                    traces[i].status != UNINITALISED;
         i++) {
        volatile trace_info_t *trace = &traces[i];
        if (trace->status == FAILED)
            continue;
        trace_join(trace->trace);
        if (trace->status != STOPPED)
            fprintf(stderr, "Trace stopped of its own accord: " PRItrace "\n",
                    printable(trace));
        fprintf(stderr, "Joined: " PRItrace "\n", printable(trace));
        if (trace_is_err(trace->trace)) {
            trace_perror(trace->trace, "ERROR joining trace (" PRItrace ")",
                         printable(trace));
            trace_destroy(trace->trace);
            trace->trace = NULL;
            trace->status = FAILED;
        } else {
            trace_destroy(trace->trace);
            trace->trace = NULL;
            trace->status = JOINT;
        }
    }

    trace_destroy_callback_set(pktcbs);

    print_full_status();
    for (int i = 0; i < MAX_TRACES; i++) {
        if (traces[i].status == FAILED)
            return 1;
    }

    return 0;
}
