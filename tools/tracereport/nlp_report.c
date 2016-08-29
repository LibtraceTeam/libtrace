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

static stat_t nlp_stat[3][65536] = {{{0,0}}} ;

void nlp_per_packet(struct libtrace_packet_t *packet)
{
	uint16_t ethertype;
	void *link;
	libtrace_direction_t dir = trace_get_direction(packet);

	link = trace_get_layer3(packet,&ethertype,NULL);
	
	if (!link)
		return;

	if (dir != TRACE_DIR_INCOMING && dir != TRACE_DIR_OUTGOING)
		dir = TRACE_DIR_OTHER;
	
	nlp_stat[dir][ethertype].count++;
	nlp_stat[dir][ethertype].bytes+=trace_get_wire_length(packet);
}

void nlp_report(void){
	int i,j;
	
	FILE *out = fopen("nlp.rpt", "w");
	if (!out) {
		perror("fopen");
		return;
	}
	
	/* Put some headings up for human-readability */
	fprintf(out, "%-12s\t%10s\t%16s %16s\n",
			"NETWORK LAYER",
			"DIRECTION",
			"BYTES",
			"PACKETS");
	for(i = 0; i < 65536; i++){
		if (nlp_stat[0][i].count==0 && 
			nlp_stat[1][i].count==0 && nlp_stat[2][i].count==0)
			continue;
		switch(i){
			case 0x0800: 
				fprintf(out, "%12s", "IPv4 |");
				break;
			case 0x0806: 
				fprintf(out, "%12s", "ARP |");
				break;
			case 0x8137:
				fprintf(out, "%12s", "IPX |");
				break;
			case 0x814C:
				fprintf(out, "%12s", "SNMP |");
				break;
			case 0x86DD:
				fprintf(out, "%12s", "IPv6 |");
				break;
			case 0x880B:
				fprintf(out, "%12s", "PPP |");
				break;
			default:
				fprintf(out, "%10i |",i);
		}
		for(j=0;j<3;j++){
			if (j != 0) {
				fprintf(out, "%12s", " |");
			}

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
				nlp_stat[j][i].bytes,
				nlp_stat[j][i].count);
		}
	}
	fclose(out);
}
