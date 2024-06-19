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
 * $Id: test-pcap-to-erf.c,v 1.3 2006/02/27 03:41:12 perry Exp $
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

#include "dagformat.h"
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

void iferrout(libtrace_out_t *trace)
{
    libtrace_err_t err = trace_get_err_output(trace);
    if (err.err_num == 0)
        return;
    printf("Error: %s\n", err.problem);
    exit(1);
}

char *lookup_uri(const char *type)
{
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
    if (!strcmp(type, "legacyatm"))
        return "legacyatm:traces/legacyatm.gz";
    if (!strcmp(type, "legacypos"))
        return "legacypos:traces/legacypos.gz";
    if (!strcmp(type, "legacyeth"))
        return "legacyeth:traces/legacyeth.gz";
    if (!strcmp(type, "duck"))
        return "duck:traces/100_packets.duck";
    if (!strcmp(type, "tsh"))
        return "tsh:traces/10_packets.tsh.gz";
    return "unknown";
}

char *lookup_out_uri(const char *type)
{
    if (!strcmp(type, "erf"))
        return "erf:traces/100_packets.out.erf";
    if (!strcmp(type, "pcap"))
        return "pcap:traces/100_packets.out.pcap";
    if (!strcmp(type, "pcapfile"))
        return "pcapfile:traces/100_packets.out.pcap";
    if (!strcmp(type, "wtf"))
        return "wtf:traces/wed.out.wtf";
    if (!strcmp(type, "duck"))
        return "duck:traces/100_packets.out.duck";
    return "unknown";
}

int convert_fail(libtrace_packet_t *p1, libtrace_packet_t *p2)
{

    libtrace_linktype_t l1, l2;

    int cap1, cap2, wire1, wire2;

    l1 = trace_get_link_type(p1);
    l2 = trace_get_link_type(p2);

    cap1 = trace_get_capture_length(p1);
    cap2 = trace_get_capture_length(p2);

    wire1 = trace_get_wire_length(p1);
    wire2 = trace_get_wire_length(p2);

    /* If the capture lengths are not the same, it may be because the
     * packet has been truncated - the important thing then is that the
     * wire lengths match */
    if (cap1 != cap2) {

        /* Check for truncation */
        if (cap2 == wire2)
            return 0;

        /* Check that the wire length is unchanged */
        if (wire1 == wire2)
            return 0;

        /* There is no matching DLT for ATM, so we have to demote the
         * packet to LLCSNAP when converting to pcap. The demotion
         * loses 4 bytes of ATM header, but we need to allow for that
         */
        if (l1 == TRACE_TYPE_ATM && l2 == TRACE_TYPE_LLCSNAP) {
            if (wire1 - wire2 == 4)
                return 0;
        }

        return 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int psize = 0;
    int error = 0;
    uint64_t count = 0;
    int level = 0;
    int tcpcount = 0;
    libtrace_t *trace, *trace2;
    libtrace_out_t *outtrace;
    libtrace_packet_t *packet, *packet2;
    const char *trace1name;
    const char *trace2name;

    if (argc < 3) {
        fprintf(stderr, "Missing traces as arguments\n");
        return -1;
    }

    trace = trace_create(argv[1]);
    iferr(trace);

    outtrace = trace_create_output(argv[2]);
    iferrout(outtrace);

    level = 0;
    trace_config_output(outtrace, TRACE_OPTION_OUTPUT_COMPRESS, &level);
    if (trace_is_err_output(outtrace)) {
        trace_perror_output(outtrace, "WARNING: ");
    }

    trace_start(trace);
    iferr(trace);
    trace_start_output(outtrace);
    iferrout(outtrace);

    packet = trace_create_packet();
    for (;;) {
        if ((psize = trace_read_packet(trace, packet)) < 0) {
            error = 1;
            break;
        }
        if (psize == 0) {
            error = 0;
            break;
        }
        count++;
        trace_write_packet(outtrace, packet);
        iferrout(outtrace);
    }
    trace_destroy_packet(packet);
    if (error != 0) {
        iferr(trace);
    }
    trace_destroy(trace);
    trace_destroy_output(outtrace);

    if (error)
        return error;

    /* Now read it back in again and check it's all kosher */
    trace1name = argv[1];
    trace = trace_create(trace1name);
    iferr(trace);
    trace_start(trace);
    trace2name = (argv[2]);
    trace2 = trace_create(trace2name);
    iferr(trace2);
    trace_start(trace2);
    iferr(trace2);
    packet = trace_create_packet();
    packet2 = trace_create_packet();
    count = 0;
    tcpcount = 0;
    while (trace_read_packet(trace, packet) > 0) {
        int err;
        ++count;
        if ((err = trace_read_packet(trace2, packet2)) < 1) {
            printf("premature EOF on destination, %" PRIu64 " from %s, %" PRIu64
                   " from %s\n",
                   count, lookup_uri(argv[1]), count - 1,
                   lookup_out_uri(argv[2]));
            iferr(trace2);
            error = 1;
            break;
        }
        /* The capture length might be snapped down to the wire length */
        if (convert_fail(packet, packet2)) {
            printf("\t%s\t%s\n", trace1name, trace2name);
            printf("packet\t%" PRIu64 "\n", count);
            printf("caplen\t%zd\t%zd\t%+zd\n", trace_get_capture_length(packet),
                   trace_get_capture_length(packet2),
                   trace_get_capture_length(packet2) -
                       trace_get_capture_length(packet));
            printf("wirelen\t%zd\t%zd\t%+zd\n", trace_get_wire_length(packet),
                   trace_get_wire_length(packet2),
                   trace_get_wire_length(packet2) -
                       trace_get_wire_length(packet));
            printf("link\t%d\t%d\n", trace_get_link_type(packet),
                   trace_get_link_type(packet2));
            abort();
        }

        if (trace_get_tcp(packet)) {
            if (!trace_get_tcp(packet2)) {
                printf("trace corrupt -- expected tcp\n");

                // trace_dump_packet(packet);
                trace_hexdump_packet(packet);
                printf("\n");
                // trace_dump_packet(packet2);
                trace_hexdump_packet(packet2);

                error = 1;
                break;
            }
            ++tcpcount;
        } else {
            if (trace_get_tcp(packet2)) {
                printf("trace corrupt: unexpected tcp\n");
                error = 1;
                break;
            }
        }
    }
    if (count != 0 && trace_read_packet(trace2, packet2) > 0) {
        printf("Extra packets after EOF\n");
        error = 1;
    }
    trace_destroy(trace);
    trace_destroy(trace2);
    trace_destroy_packet(packet);
    trace_destroy_packet(packet2);

    // printf("tcpcount=%i\n",tcpcount);

    return error;
}
