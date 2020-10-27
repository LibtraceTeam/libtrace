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
#include <netinet/in.h>
#include <stdio.h>
#include "libpacketdump.h"
#include "libtrace.h"

DLLEXPORT void decode(int link_type UNUSED, const char *packet, unsigned len)
{
	libtrace_ip6_frag_t *frag = (libtrace_ip6_frag_t *)packet;
	uint16_t offset;

	// IPv6 Fragment Header
	if (len == 0) {
		printf(" IPv6 Frag: [Truncated]\n");
		return;
	}

	

	printf(" IPv6 Frag: Next Header: %u\n", frag->nxt);
	
	offset = ntohs(frag->frag_off);
	printf(" IPv6 Frag: Offset: %u", offset & 0xFFF8);
	if ((offset & 0x1)) printf(" MORE_FRAG");
	
	printf("\n"); 
	printf(" IPv6 Frag: Identification: %u\n", ntohl(frag->ident));

	/* Only dump the next header if this is the first fragment */
	if ((offset & 0xFFF8) != 0)
		return;

	decode_next(packet + sizeof(libtrace_ip6_frag_t), 
			len - sizeof(libtrace_ip6_frag_t), "ip", frag->nxt);
	return;	

}
