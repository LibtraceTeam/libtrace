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


#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"
#include "report.h"

static uint64_t dir_bytes[8];
static uint64_t dir_packets[8];

void dir_per_packet(struct libtrace_packet_t *packet)
{
	if (trace_get_direction(packet)==-1)
		return;
	dir_bytes[trace_get_direction(packet)]+=trace_get_wire_length(packet);
	++dir_packets[trace_get_direction(packet)];
}

void dir_report(void)
{
	int i;
	FILE *out = fopen("dir.rpt", "w");
	if (!out) {
		perror("fopen");
		return;
	}
	fprintf(out, "%-20s \t%12s\t%12s\n","DIRECTION","BYTES","PACKETS");
	for(i=0;i<8;++i) {
		if (!dir_packets[i])
			continue;
		switch(i) {
			case TRACE_DIR_INCOMING: fprintf(out, "%20s:\t%12" PRIu64 "\t%12" PRIu64 "\n",
					"Incoming",dir_bytes[i],dir_packets[i]);
				break;
			case TRACE_DIR_OUTGOING: fprintf(out, "%20s:\t%12" PRIu64 "\t%12" PRIu64 "\n",
					"Outgoing",dir_bytes[i],dir_packets[i]);
				break;
			case TRACE_DIR_OTHER: fprintf(out, "%20s:\t%12" PRIu64 "\t%12" PRIu64 "\n",
					"Other",dir_bytes[i],dir_packets[i]);
				break;
			default: fprintf(out, "%20i:\t%12" PRIu64 "\t%12" PRIu64 "\n",
					i,dir_bytes[i],dir_packets[i]);
				break;
		}
	}
	fclose(out);
}
