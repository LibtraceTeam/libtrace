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
