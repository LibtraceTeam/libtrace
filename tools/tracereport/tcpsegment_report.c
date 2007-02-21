#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"

static stat_t tcpseg_stat[4][2048] = {{{0,0}}} ;
static bool suppress[4] = {true,true,true,true};

void tcpseg_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_tcp *tcp = trace_get_tcp(packet);
	if (!tcp)
		return;
	int dir = trace_get_direction(packet);
	if(dir < 0 || dir > 1)
		dir = 2;
	
	int a = trace_get_wire_length(packet);
	a -= 34;

	tcpseg_stat[dir][a].count++;
	tcpseg_stat[dir][a].bytes+=trace_get_wire_length(packet);
	suppress[dir] = false;
}

void tcpseg_suppress()
{
	int i;
	printf("%-20s","Direction:");
	for(i=0;i<4;i++){
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
	for(i=0;i<4;i++){
		if(!suppress[i]){
			printf("\t%12s\t%12s", "bytes","packets");
		}
	}
	printf("\n");
}

void tcpseg_report(void)
{
	int i,j;
	printf("# TCP Segment Size breakdown:\n");
	tcpseg_suppress();
	for(i=0;i<2048;++i) {
		if (tcpseg_stat[0][i].count==0 && 
			tcpseg_stat[1][i].count==0 && tcpseg_stat[2][i].count==0)
			continue;
		printf("%20i:",i);
		for(j=0;j<4;j++){
			if (tcpseg_stat[j][i].count==0){
				if(!suppress[j])
					printf("\t%24s"," ");
				continue;
			}
			printf("\t%12" PRIu64 "\t%12" PRIu64,
				tcpseg_stat[j][i].bytes,
				tcpseg_stat[j][i].count);
		}
		printf("\n");
	}
}
