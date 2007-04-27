#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"
#include "report.h"

static stat_t prot_stat[3][256] = {{{0,0}}} ;
static bool suppress[3] = {true,true,true};

void protocol_per_packet(struct libtrace_packet_t *packet)
{
	uint8_t proto;
	libtrace_direction_t dir = trace_get_direction(packet);
	
	if (trace_get_transport(packet,&proto,NULL)==NULL)
		return;
		
	if (dir != TRACE_DIR_INCOMING && dir != TRACE_DIR_OUTGOING)
		dir = TRACE_DIR_OTHER;
	
	prot_stat[dir][proto].count++;
	prot_stat[dir][proto].bytes+=trace_get_wire_length(packet);
	suppress[dir] = false;
}

void protocol_report(void)
{
	int i,j;
	FILE *out = fopen("protocol.rpt", "w");
	if (!out) {
		perror("fopen");
		return;
	}
	fprintf(out, "%-16s\t%10s\t%16s %16s\n",
			"PROTOCOL",
			"DIRECTION",
			"BYTES",
			"PACKETS");
	
	setprotoent(1);
	for(i=0;i<256;++i) {
		struct protoent *prot;
		if (prot_stat[0][i].count==0 && 
			prot_stat[1][i].count==0 && prot_stat[2][i].count==0)
			continue;
		prot = getprotobynumber(i);
		if (prot) {
			fprintf(out, "%16s",prot->p_name);
		}
		else {
			fprintf(out, "%16i:",i);
		}
		for (j=0; j < 3; j++) {
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
                                        prot_stat[j][i].bytes,
                                        prot_stat[j][i].count);
                }
	}

	setprotoent(0);
	fclose(out);
}
