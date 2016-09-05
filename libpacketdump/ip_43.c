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

DLLEXPORT void decode(int link_type UNUSED, const char *packet, unsigned len) {

	uint16_t hbh_len = 0;
	libtrace_ip6_ext_t* hdr = (libtrace_ip6_ext_t*)packet;

	hbh_len = (hdr->len + 1) * 8;

	printf(" IPv6 Routing Header: Next Header %u Header Ext Len %u",
			hdr->nxt, hdr->len);
	printf("\n IPv6 Routing Header: Routing Type %u Segments Left %u",
			*packet, *(packet + 1));		
	printf("\n");

	decode_next(packet + hbh_len, len - hbh_len, "ip", hdr->nxt);


}
