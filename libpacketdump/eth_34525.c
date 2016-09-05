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

	printf(" IPv6: Version %u\n", (tmp >> 28) & 0x000000f);
	printf(" IPv6: Class %u\n", (tmp >> 20) & 0x000000ff);
	printf(" IPv6: Flow Label %u\n", tmp & 0x000fffff);
	printf(" IPv6: Payload Length %u\n", ntohs(ip->plen));
	printf(" IPv6: Next Header %u\n", ip->nxt);
	printf(" IPv6: Hop Limit %u\n", ip->hlim);


	char ipstr[INET6_ADDRSTRLEN];                             
	inet_ntop(AF_INET6, &(ip->ip_src), ipstr, INET6_ADDRSTRLEN);

	printf(" IPv6: Source IP %s\n", ipstr);
	inet_ntop(AF_INET6, &(ip->ip_dst), ipstr, INET6_ADDRSTRLEN);
	printf(" IPv6: Destination IP %s\n", ipstr);

	decode_next(packet+sizeof(libtrace_ip6_t),len-sizeof(libtrace_ip6_t),"ip",ip->nxt);
	return;
}
