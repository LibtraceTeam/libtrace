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
