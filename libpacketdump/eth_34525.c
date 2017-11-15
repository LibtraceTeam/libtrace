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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "libpacketdump.h"
#ifndef WIN32
	#include <netinet/in_systm.h>
#endif
#include <arpa/inet.h>
#include <netdb.h>

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	libtrace_ip6_t *ip = (libtrace_ip6_t*)packet;
	uint32_t tmp = ntohl(*(uint32_t*)ip);

        int truncated = 0;
        char ipstr[INET6_ADDRSTRLEN];

        do {
                if (len < 4) {
                        truncated = 1;
                        break;
                }

        	printf(" IPv6: Version %u\n", (tmp >> 28) & 0x000000f);
        	printf(" IPv6: Class %u\n", (tmp >> 20) & 0x000000ff);
	        printf(" IPv6: Flow Label %u\n", tmp & 0x000fffff);

                if (len < 6) {
                        truncated = 1;
                        break;
                }
        	printf(" IPv6: Payload Length %u\n", ntohs(ip->plen));

                if (len < 7) {
                        truncated = 1;
                        break;
                }
        	printf(" IPv6: Next Header %u\n", ip->nxt);
                if (len < 8) {
                        truncated = 1;
                        break;
                }
	        printf(" IPv6: Hop Limit %u\n", ip->hlim);

                if (len < 24) {
                        truncated = 1;
                        break;
                }

	        inet_ntop(AF_INET6, &(ip->ip_src), ipstr, INET6_ADDRSTRLEN);
        	printf(" IPv6: Source IP %s\n", ipstr);

                if (len < 40) {
                        truncated = 1;
                        break;
                }

                inet_ntop(AF_INET6, &(ip->ip_dst), ipstr, INET6_ADDRSTRLEN);
        	printf(" IPv6: Destination IP %s\n", ipstr);
        } while (0);

        if (truncated) {
                printf(" IPv6: [Truncated]\n");
                return;
        }

	decode_next(packet+sizeof(libtrace_ip6_t),len-sizeof(libtrace_ip6_t),"ip",ip->nxt);
	return;
}
