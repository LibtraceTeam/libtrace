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
#include <arpa/inet.h>
#include "libpacketdump.h"

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len) {
	libtrace_ospf_network_lsa_v2_t *net;
	struct in_addr *router = NULL;

	net = (libtrace_ospf_network_lsa_v2_t *)packet;

	if (len < 4)
		return;
	printf(" OSPF Network LSA: Netmask %s\n", inet_ntoa(net->netmask));

	router = (struct in_addr *)(packet + sizeof(libtrace_ospf_network_lsa_v2_t));
	len -= sizeof(libtrace_ospf_network_lsa_v2_t);

	while (len >= sizeof(struct in_addr)) {

		printf("OSPF Network LSA: Attached Router %s\n", 
				inet_ntoa(*router));
		router ++;
		len -= sizeof(struct in_addr);
	}
}
