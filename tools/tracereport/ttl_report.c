#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"
#include "report.h"

static stat_t ttl_stat[3][256] = {{{0,0}}} ;
static bool suppress[3] = {true,true,true};

void ttl_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_ip *ip = trace_get_ip(packet);
	libtrace_direction_t dir = trace_get_direction(packet);
	
	if (!ip)
		return;
	
	if (dir != TRACE_DIR_INCOMING && dir != TRACE_DIR_OUTGOING)
		dir = TRACE_DIR_OTHER;
	
	ttl_stat[dir][ip->ip_ttl].count++;
	ttl_stat[dir][ip->ip_ttl].bytes+=trace_get_wire_length(packet);
	suppress[dir] = false;
}

	

void ttl_report(void)
{
	int i,j;
	FILE *out = fopen("ttl.rpt", "w");
	if (!out) {
		perror("fopen");
		return;
	}
	fprintf(out, "%-12s\t%10s\t%16s %16s\n",
			"TTL",
			"DIRECTION",
			"BYTES",
			"PACKETS");
	for(i=0;i<256;++i) {
		if (ttl_stat[0][i].count==0 && 
			ttl_stat[1][i].count==0 && ttl_stat[2][i].count==0)
			continue;
		fprintf(out, "%12i:",i);
		for(j=0;j<3;j++){
			if (j != 0) {
				fprintf(out, "%12s", " ");
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
					ttl_stat[j][i].bytes,
					ttl_stat[j][i].count);
		}
	}
	fclose(out);
}
