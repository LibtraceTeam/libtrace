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

static stat_t tcpopt_stat[3][256] = {{{0,0}}};

void tcpopt_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_tcp *tcp = trace_get_tcp(packet);
	unsigned char *opt_ptr;
	libtrace_direction_t dir = trace_get_direction(packet);
	int tcp_payload, len;
	unsigned char type, optlen, *data;
	
	if(!tcp)
		return;
	
	if (dir != TRACE_DIR_INCOMING && dir != TRACE_DIR_OUTGOING)
		dir = TRACE_DIR_OTHER;
	
	len = tcp->doff * 4 - sizeof(libtrace_tcp_t);
	if(len == 0)
		return;
	
	tcp_payload = trace_get_wire_length(packet) - trace_get_capture_length(packet);
	
	opt_ptr = (unsigned char *)tcp + sizeof (libtrace_tcp_t);
	
	while(trace_get_next_option(&opt_ptr,&len,&type,&optlen,&data)){
		/* I don't think we need to count NO-OPs */
		if (type == 1)
			continue;
		tcpopt_stat[dir][type].count++;
		tcpopt_stat[dir][type].bytes+= tcp_payload;
	}
	
}


void tcpopt_report(void)
{
	
	int i,j;
	
	FILE *out = fopen("tcpopt.rpt", "w");
	if (!out) {
		perror("fopen");
		return;
	}

	/* Put some headings up for human-readability */
	fprintf(out, "%-12s\t%10s\t%16s %16s\n",
			"OPTION",
			"DIRECTION",
			"BYTES",
			"PACKETS");
	
	for(i=0;i<256;++i) {
		if (tcpopt_stat[0][i].count==0 && 
			tcpopt_stat[1][i].count==0 && tcpopt_stat[2][i].count==0)
			continue;
		
		switch(i) {
			case 1:
				fprintf(out, "%12s", "NOP |");
				break;
			case 2:
				fprintf(out, "%12s", "MSS |");
				break;
			case 3:
				fprintf(out, "%12s", "Winscale |");
				break;
			case 4:
				fprintf(out, "%12s", "SACK Perm |");
				break;
			case 5:
				fprintf(out, "%12s", "SACK Info |");
				break;
			case 8:
				fprintf(out, "%12s", "Timestamp |");
				break;
			case 12:
				fprintf(out, "%12s", "CC.New |");
				break;
			case 19:
				fprintf(out, "%12s", "MD5 |");
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
				tcpopt_stat[j][i].bytes,
				tcpopt_stat[j][i].count);
		}
	}
	fclose(out);
}
