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
