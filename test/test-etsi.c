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
 */
#ifndef WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "libtrace.h"

void iferr(libtrace_t *trace, const char *msg) {
        libtrace_err_t err = trace_get_err(trace);
        if (err.err_num == 0)
                return;
        printf("Error: %s: %s\n", msg, err.problem);
        exit(1);
}

void usage(char *argv[]) {
        fprintf(stderr, "usage: %s packets timeout trace\n", argv[0]);
        fprintf(stderr, "\tpackets: The expected number of packets\n"
                        "\ttimeout: The timeout in seconds\n"
                        "\ttrace: The trace format\n");
}

static void sig_handler(int sig UNUSED) {
        trace_interrupt();
}

static int parse_int_or_exit(char *arg, char *argmsg, int min, int max,
                             char *argv[]) {
        char *end = NULL;
        int ret;
        errno = 0;
        ret = strtol(arg, &end, 0);
        if (errno || '\0' != *end || ret <= min || ret > max) {
                fprintf(stderr, "Cannot parse argument '%s' as an integer.\n",
                        argmsg);
                usage(argv);
                exit(1);
        }
        return ret;
}

int main(int argc, char *argv[]) {
        int psize = 0;
        int error = 0;
        int count = 0;
        int expected = 100;
        const char *tracename;
        libtrace_t *trace;
        libtrace_packet_t *packet;
        int timeout = 0;

        if (argc != 4) {
                usage(argv);
                return 1;
        }

        errno = 0;
        expected = parse_int_or_exit(argv[1], "expected", 0, INT_MAX, argv);
        timeout = parse_int_or_exit(argv[2], "timeout", -1, INT_MAX, argv);
        tracename = argv[3];

        trace = trace_create(tracename);
        iferr(trace, tracename);

        trace_start(trace);
        iferr(trace, tracename);

        signal(SIGINT, &sig_handler);
        signal(SIGALRM, &sig_handler);

        packet = trace_create_packet();
        for (;;) {
                if ((psize = trace_read_packet(trace, packet)) < 0) {
                        error = 1;
                        iferr(trace, tracename);
                        break;
                }
                if (psize == 0) {
                        error = 0;
                        break;
                }
                /* Set the timeout after seeing the first packet */
                if (timeout) {
                        alarm(timeout);
                        timeout = 0;
                }
                count++;
                if (count > 100)
                        break;
        }
        trace_destroy_packet(packet);
        if (error == 0) {
                if (count == expected) {
                        printf("success: %d packets read\n", expected);
                } else {
                        printf("failure: %d packets expected, %d seen\n",
                               expected, count);
                        error = 1;
                }
        } else {
                iferr(trace, tracename);
        }
        trace_destroy(trace);
        return error;
}
