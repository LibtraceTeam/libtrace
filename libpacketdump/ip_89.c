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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libpacketdump.h"

static void dump_ospf_v2_header(libtrace_ospf_v2_t *hdr, unsigned len) {

	DISPLAY(hdr, ospf_v, " OSPF Header: Version %u");
        DISPLAY(hdr, type, " Type %u ");
	switch(hdr->type) {
		case TRACE_OSPF_HELLO:
			printf("(Hello)");
			break;
		case TRACE_OSPF_DATADESC:
			printf("(Database Desc)");
			break;
		case TRACE_OSPF_LSREQ:
			printf("(Link State Request)");
			break;
		case TRACE_OSPF_LSUPDATE:
			printf("(Link State Update)");
			break;
		case TRACE_OSPF_LSACK:
			printf("(Link State Ack.)");
			break;
	}
        printf("\n");

	DISPLAYS(hdr, ospf_len, "OSPF Header: Length %u \n");
        DISPLAYIP(hdr, router, " OSPF Header: Router Id %s ");
        DISPLAYIP(hdr, area, "Area Id %s\n");
	DISPLAYS(hdr, sum, " OSPF Header: Checksum %u ");
        DISPLAYS(hdr, au_type, "Auth Type %u\n");
        DISPLAY(hdr, au_key_id, " OSPF Header: Auth Key ID %u ");
        DISPLAY(hdr, au_data_len, "Auth Data Len %u\n");
        DISPLAYL(hdr, au_seq_num, " OSPF Header: Auth Crypto Seq %u\n");

}

DLLEXPORT void decode(int link_type UNUSED, const char *packet, unsigned len) {

	libtrace_ospf_v2_t *hdr = (libtrace_ospf_v2_t *)packet;

	if (hdr->ospf_v == 2) {
		dump_ospf_v2_header(hdr, len);
		decode_next(packet + sizeof(libtrace_ospf_v2_t), 
			len - sizeof(libtrace_ospf_v2_t), "ospf2", 
			hdr->type);
	}

	return;

}
