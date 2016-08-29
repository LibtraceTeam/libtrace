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

#define MAX_SEG_SIZE 10000

static stat_t tcpseg_stat[3][MAX_SEG_SIZE + 1] = {{{0,0}}} ;
static bool suppress[3] = {true,true,true};

void tcpseg_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_tcp *tcp = trace_get_tcp(packet);
	libtrace_ip_t *ip = trace_get_ip(packet);
	libtrace_direction_t dir = trace_get_direction(packet);
	int ss;
	uint16_t ip_len ;
	
	if (!tcp || !ip)
		return;

	if (dir != TRACE_DIR_INCOMING && dir != TRACE_DIR_OUTGOING)
		dir = TRACE_DIR_OTHER;
	
	ip_len = ntohs(ip->ip_len);
	ss = ip_len - (ip->ip_hl * 4);

	if (ss > MAX_SEG_SIZE) {
		fprintf(stderr, "Maximum segment size %u exceeded - size was %u\n",
				MAX_SEG_SIZE, ss);
		return;
	}


	tcpseg_stat[dir][ss].count++;
	tcpseg_stat[dir][ss].bytes+=trace_get_wire_length(packet);
	suppress[dir] = false;
}

void tcpseg_report(void)
{
	int i,j;
	FILE *out = fopen("tcpseg.rpt", "w");
	if (!out) {
		perror("fopen");
		return;
	}
	fprintf(out, "%-16s\t%10s\t%16s %16s\n",
			"SEGMENT SIZE",
			"DIRECTION",
			"BYTES",
			"PACKETS");
	
	for(i=0;i<2048;++i) {
		bool indent_needed;
		if (tcpseg_stat[0][i].count==0 && 
			tcpseg_stat[1][i].count==0 && tcpseg_stat[2][i].count==0)
			continue;
		fprintf(out, "%16i:",i);
		indent_needed=false;
		for(j=0;j<3;j++){
			if (indent_needed) {
				fprintf(out, "%16s", " ");
			}
			if (suppress[j])
				continue;
			switch (j) {
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
				tcpseg_stat[j][i].bytes,
				tcpseg_stat[j][i].count);	
			indent_needed=true;
		}
	}
	fclose(out);
}
