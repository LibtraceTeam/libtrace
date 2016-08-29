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

static stat_t tos_stat[3][256] = {{{0,0}}} ;
static bool suppress[3] = {true,true,true};

void tos_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_ip *ip = trace_get_ip(packet);
	libtrace_direction_t dir = trace_get_direction(packet);
	
	if (!ip)
		return;
	
	if (dir != TRACE_DIR_INCOMING && dir != TRACE_DIR_OUTGOING)
		dir = TRACE_DIR_OTHER;
	
	tos_stat[dir][ip->ip_tos].count++;
	tos_stat[dir][ip->ip_tos].bytes+=trace_get_wire_length(packet);
	suppress[dir] = false;
}


void tos_report(void)
{
	int i,j;
	FILE *out = fopen("tos.rpt", "w");
	if (!out) {
		perror("fopen");
		return;
	}
	
	fprintf(out, "%-12s\t%10s\t%16s %16s\n",
			"TOS",
			"DIRECTION",
			"BYTES",
			"PACKETS");
	
	
	for(i=0;i<256;++i) {
		if (tos_stat[0][i].count==0 && 
			tos_stat[1][i].count==0 && tos_stat[2][i].count==0)
			continue;
		fprintf(out, "%12i:",i);
		for(j=0;j<3;j++){
			if (j != 0) {
				fprintf(out, "%12s", " ");
			}
			switch(j) {
				case 0:
					fprintf(out, "\t%10s", "Outbound");
					break;
				case 1:
					fprintf(out, "\t%10s", "Inbound");
					break;
				case 2:
					fprintf(out, "\t%10s", "Unknown");
					break;
			}
			fprintf(out, "\t%16" PRIu64 " %16" PRIu64 "\n",
				tos_stat[j][i].bytes,
				tos_stat[j][i].count);
		}
	}
	fclose(out);
}
