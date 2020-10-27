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
#include <inttypes.h>
#include <dlfcn.h>
#include "libtrace.h"
#include "libpacketdump.h"

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	char ether_buf[18] = {0, };
	printf(" Ethernet:");
	if (len>=6)
		printf(" Dest: %s",trace_ether_ntoa((uint8_t *)packet, 
					ether_buf));
	else {
		printf("[|Truncated]\n");
		return;
	}
	if (len>=12) 
		printf(" Source: %s",trace_ether_ntoa((uint8_t*)(packet+6), 
					ether_buf));
	else {
		printf("[|Truncated]\n");
		return;
	}
	if (len>=14) {
		uint16_t type = htons(*(uint16_t*)(packet+12));
		printf(" Ethertype: 0x%04x\n",type);
		decode_next(packet+14,len-14,"eth",type);
	}
	else {
		printf("[|Truncated]\n");
		return;
	}
	return;
}
