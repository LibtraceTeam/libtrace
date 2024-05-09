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
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>

#include "libtrace.h"
#include "libpacketdump.h"

void iferr(libtrace_t *trace)
{
    libtrace_err_t err = trace_get_err(trace);
    if (err.err_num == 0)
        return;
    printf("Error: %s\n", err.problem);
    exit(1);
}

const char *lookup_uri(const char *type)
{
    if (strchr(type, ':'))
        return type;
    if (!strcmp(type, "erf"))
        return "erf:traces/100_packets.erf";
    if (!strcmp(type, "pcap"))
        return "pcap:traces/100_packets.pcap";
    if (!strcmp(type, "wtf"))
        return "wtf:traces/wed.wtf";
    if (!strcmp(type, "rtclient"))
        return "rtclient:chasm";
    if (!strcmp(type, "pcapfile"))
        return "pcapfile:traces/100_packets.pcap";
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
    if (!strcmp(type, "legacylarge"))
        return "legacyatm:traces/large_legacy.gz";
    return type;
}

int main(int argc, char *argv[])
{
    int psize = 0;
    libtrace_t *trace;
    libtrace_packet_t *packet;
    int error;

    if (argc < 2) {
        fprintf(stderr, "usage: %s type\n", argv[0]);
        return 1;
    }

    trace = trace_create(lookup_uri(argv[1]));
    iferr(trace);

    trace_start(trace);
    iferr(trace);

    packet = trace_create_packet();
    for (;;) {
        if ((psize = trace_read_packet(trace, packet)) < 0) {
            error = 1;
            iferr(trace);
            break;
        }
        if (psize == 0) {
            error = 0;
            break;
        }
    }
    trace_destroy_packet(packet);

    if (error == 0) {
        uint64_t f;
        f = trace_get_received_packets(trace);
        if (f != UINT64_MAX)
            fprintf(stderr, "%" PRIu64 " packets on input\n", f);
        f = trace_get_filtered_packets(trace);
        if (f != UINT64_MAX)
            fprintf(stderr, "%" PRIu64 " packets filtered\n", f);
        f = trace_get_dropped_packets(trace);
        if (f != UINT64_MAX)
            fprintf(stderr, "%" PRIu64 " packets dropped\n", f);
        f = trace_get_accepted_packets(trace);
        if (f != UINT64_MAX)
            fprintf(stderr, "%" PRIu64 " packets accepted\n", f);
    } else {
        iferr(trace);
    }
    trace_destroy(trace);
    return error;
}
