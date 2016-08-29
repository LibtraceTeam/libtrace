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
/* Decoder for CHDLC frames */

#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libtrace.h"
#include "libpacketdump.h"

typedef struct libtrace_chdlc_t {
        uint8_t address;        /** 0xF0 for unicast, 0xF8 for multicast */
        uint8_t control;        /** Always 0x00 */
        uint16_t ethertype;
} libtrace_chdlc_t;


DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	libtrace_chdlc_t *frame = (libtrace_chdlc_t *)packet;

	printf(" CHDLC:");
	if (len >= 1)
		printf(" Address: 0x%02x", frame->address);
	else {
		printf("[|Truncated]\n");
		return;
	}
	
	if (len >= 2)
		printf(" Control: 0x%02x", frame->control);
	else {
		printf("[|Truncated]\n");
		return;
	}
	
	if (len >= 4) {
		printf(" Ethertype: 0x%04x\n", ntohs(frame->ethertype));
		decode_next(packet + 4, len - 4, "eth", 
				ntohs(frame->ethertype));
	}
	else {
		printf("[|Truncated]\n");
		return;
	}
	

	return;
}
