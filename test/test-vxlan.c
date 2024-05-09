/*
 * This file is part of libtrace
 *
 * Copyright (c) 2015 The University of Waikato, Hamilton, New Zealand.
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

int main(int argc, char *argv[])
{
    int psize = 0;
    int error = 0;
    int ip_count = 0;
    int arp_count = 0;
    libtrace_t *trace;
    libtrace_packet_t *packet;

    (void)argc;
    (void)argv;

    trace = trace_create("pcapfile:traces/vxlan.pcap");
    iferr(trace);

    trace_start(trace);
    iferr(trace);

    packet = trace_create_packet();
    for (;;) {
        uint8_t proto;
        uint32_t remaining;
        void *transport;
        void *layer2;
        void *vxlan;

        if ((psize = trace_read_packet(trace, packet)) < 0) {
            error = 1;
            iferr(trace);
            break;
        }
        if (psize == 0) {
            break;
        }

        transport = trace_get_transport(packet, &proto, &remaining);
        if (proto != TRACE_IPPROTO_UDP) {
            printf("Failed to find a UDP header\n");
            error = 1;
            continue;
        }

        vxlan = trace_get_vxlan_from_udp(transport, &remaining);
        if (!vxlan) {
            printf("Failed to find a VXLAN header\n");
            error = 1;
            continue;
        }

        layer2 = trace_get_payload_from_vxlan(vxlan, &remaining);

        switch (ntohs(((libtrace_ether_t *)layer2)->ether_type)) {
        case 0x0800:
            ip_count++;
            break;
        case 0x0806:
            arp_count++;
            break;
        default:
            fprintf(stderr, "Unexpected vxlan ethertype: %08x\n",
                    ntohs(((libtrace_ether_t *)layer2)->ether_type));
            error = 1;
            continue;
        }
    }
    trace_destroy_packet(packet);
    if (ip_count != 8 || arp_count != 2) {
        fprintf(stderr, "Incorrect number of ip/arp packets\n");
        error = 1;
    }
    if (error == 0) {
        printf("success\n");
    } else {
        iferr(trace);
    }
    trace_destroy(trace);
    return error;
}
