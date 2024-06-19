/*
 *
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
 *
 *
 */
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libpacketdump.h"

static char *unreach_types[] = {
    "Destination Network Unreachable",
    "Destination Host Unreachable",
    "Destination Protocol Unreachable",
    "Destination Port Unreachable",
    "Fragmentation Required And Dont Fragment Set",
    "Source Route Failed",
    "Destination Network Unknown",
    "Destination Host Unknown",
    "Source Host Isolated",
    "Destination Network Administratively Prohibited",
    "Destination Host Administratively Prohibited",
    "Destination Network Unreachable For Type Of Service",
    "Destination Host Unreachable For Type Of Service",
    "Communication Administratively Prohibited",
    "Host Precedence Violation",
    "Precedence Cutoff In Effect",
};

DLLEXPORT void decode(int link_type UNUSED, const char *packet, unsigned len)
{
    libtrace_icmp_t *icmp = (libtrace_icmp_t *)packet;
    int ippresent = 0;
    if (len < 1)
        return;
    printf(" ICMP:");
    switch (icmp->type) {
    case 0:
        printf(" Type: 0 (ICMP Echo Reply) Sequence: ");
        if (len < 4)
            printf("(Truncated)\n");
        else
            printf("%u\n", ntohs(icmp->un.echo.sequence));
        break;
    case 3:
        printf(" Type: 3 (ICMP Destination Unreachable)\n");
        if (len < 2)
            return;
        if (icmp->code < sizeof(unreach_types)) {
            printf(" ICMP: Code: %i (%s)\n", icmp->code,
                   unreach_types[icmp->code]);
        } else {
            printf(" ICMP: Code: %i (Unknown)\n", icmp->code);
        }
        ippresent = 1;
        break;
    case 8:
        printf(" Type: 8 (ICMP Echo Request) Sequence: ");
        if (len < 4)
            printf("(Truncated)\n");
        else
            printf("%u\n", ntohs(icmp->un.echo.sequence));
        break;
    case 11:
        printf(" Type: 11 (ICMP TTL Exceeded)\n");
        ippresent = 1;
        break;
    default:
        printf(" Type: %i (Unknown)\n", icmp->type);
        break;
    }
    printf(" ICMP: Checksum: ");
    if (len < 8)
        printf("(Truncated)\n");
    else
        printf("%u\n", ntohs(icmp->checksum));

    if (ippresent) {
        decode_next(packet + 8, len - 8, "eth", 0x0800);
    }

    return;
}
