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
#ifndef WIN32
#    include <sys/time.h>
#    include <netinet/in.h>
#    include <netinet/in_systm.h>
#    include <netinet/tcp.h>
#    include <netinet/ip.h>
#    include <netinet/ip_icmp.h>
#    include <arpa/inet.h>
#    include <sys/socket.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>

#include "libtrace.h"

struct libtrace_t *trace;

void iferr(libtrace_t *trace)
{
    libtrace_err_t err = trace_get_err(trace);
    if (err.err_num == 0)
        return;
    printf("Error: %s\n", err.problem);
    exit(1);
}

int main(int argc UNUSED, char *argv[] UNUSED)
{
    char *uri = "erf:traces/fragtest.erf.gz";
    int error = 0;
    uint64_t totaloffset = 0;
    int morefrags = 0;
    int count = 0;
    int psize = 0;
    struct libtrace_packet_t *packet;
    uint16_t fragoff;
    uint8_t more;

    trace = trace_create(uri);
    iferr(trace);

    if (trace_start(trace) == -1) {
        iferr(trace);
    }

    packet = trace_create_packet();
    for (;;) {
        if ((psize = trace_read_packet(trace, packet)) <= 0) {
            if (psize != 0)
                error = 1;
            break;
        }
        if (psize == 0) {
            error = 0;
            break;
        }

        fragoff = trace_get_fragment_offset(packet, &more);
        totaloffset += fragoff;
        if (more)
            morefrags++;

        count++;
    }
    trace_destroy_packet(packet);
    if (error == 0) {
        if (count == 10000) {
            printf("success: 10000 packets read\n");
        } else {
            printf("fail: 10000 packets expected, %d seen\n", count);
            error = 1;
        }

        if (totaloffset == 69192) {
            printf("success: frag offset sum is 69192\n");
        } else {
            printf("fail: expected frag offset sum of 69192, got %" PRIu64 "\n",
                   totaloffset);
            error = 1;
        }

        if (morefrags == 16) {
            printf("success: counted 16 MORE_FRAG flags\n");
        } else {
            printf("fail: expected 16 MORE_FRAG flags, got %d\n", morefrags);
            error = 1;
        }

    } else {
        iferr(trace);
    }
    trace_destroy(trace);
    return error;
}
