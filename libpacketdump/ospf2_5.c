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

#include <assert.h>

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len) {

	unsigned char *lsa_ptr = (unsigned char *)packet;
	uint32_t rem = len;
	uint16_t lsa_length = 0;
	uint8_t lsa_type;
	libtrace_ospf_lsa_v2_t *lsa_hdr;

	while (trace_get_next_ospf_lsa_header_v2(&lsa_ptr, &lsa_hdr, 
                       	&rem, &lsa_type, &lsa_length) > 0) {

		if (lsa_hdr) {
			decode_next((char *)lsa_hdr, lsa_length, "ospf2", 1000);
		}

		/* These packets contain LSA headers only so don't try to
		 * decode the body */
	}
}
