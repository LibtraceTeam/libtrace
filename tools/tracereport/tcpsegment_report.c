#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"
#include "report.h"

static stat_t tcpseg_stat[3][2048] = {{{0,0}}} ;
static bool suppress[3] = {true,true,true};

void tcpseg_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_tcp *tcp = trace_get_tcp(packet);
	libtrace_ip_t *ip = trace_get_ip(packet);
	libtrace_direction_t dir = trace_get_direction(packet);
	int ss;
	uint16_t ip_len ;
	
	if (!tcp)
		return;

	if (dir != TRACE_DIR_INCOMING && dir != TRACE_DIR_OUTGOING)
		dir = TRACE_DIR_OTHER;
	
	ip_len = ntohs(ip->ip_len);
	ss = ip_len - (ip->ip_hl * 4);

	tcpseg_stat[dir][ss].count++;
	tcpseg_stat[dir][ss].bytes+=trace_get_wire_length(packet);
	suppress[dir] = false;
}

static void tcpseg_suppress()
{
	int i;
	printf("%-20s","Direction:");
	for(i=0;i<3;i++){
		if(!suppress[i]){
			switch(i){
				case 0:
					printf("\t%24s", "Outbound   ");
					break;
				case 1:
					printf("\t%24s", "Inbound   ");
					break;
				case 2:
					printf("\t%24s", "Undefined   ");
					break;
				default:
					break;
			}
		}
	}
	printf("\n");
	printf("%-20s","TCP SS");
	for(i=0;i<3;i++){
		if(!suppress[i]){
			printf("\t%12s\t%12s", "bytes","packets");
		}
	}
	printf("\n");
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
		if (tcpseg_stat[0][i].count==0 && 
			tcpseg_stat[1][i].count==0 && tcpseg_stat[2][i].count==0)
			continue;
		fprintf(out, "%16i:",i);
		for(j=0;j<3;j++){
			if (j != 0) {
				fprintf(out, "%16s", " ");
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
				tcpseg_stat[j][i].bytes,
				tcpseg_stat[j][i].count);	
		}
	}
	fclose(out);
}
