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

typedef struct gre_t {
	uint16_t flags;
	uint16_t ethertype;
	uint16_t checksum;
	uint16_t reserved1;
} gre_t;

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	// GRE
	if (len<2) {
		printf(" GRE: [Truncated]\n");
		return;
	}
	printf(" GRE: %s\n",
		ntohs(((gre_t*)packet)->flags) & 0x8000 
			? "Checksum present"
			: "Checksum absent");
	printf(" GRE: Version: %d\n", ntohs(((gre_t*)packet)->flags) & 0x0007);
	printf(" GRE: Protocol: %04x\n", ntohs(((gre_t*)packet)->ethertype));

	if (ntohs(((gre_t*)packet)->flags) & 0x8000) {
		decode_next(packet+4,len-4,"link",
				ntohs(((gre_t*)packet)->ethertype));
	}
	else {
		decode_next(packet+8,len-8,"link",
				ntohs(((gre_t*)packet)->ethertype));
	}
	return;
}
