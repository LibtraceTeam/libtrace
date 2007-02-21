#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"

static stat_t ecn_stat[4][4] = {{{0,0}}} ;
static bool suppress[4] = {true,true,true,true};

void ecn_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_ip *ip = trace_get_ip(packet);
	if (!ip)
		return;
	int dir = trace_get_direction(packet);
	if(dir < 0 || dir > 1)
		dir = 2;
	
	int ecn = ip->ip_tos;
	ecn &= 3;
	ecn_stat[dir][ecn].count++;
	ecn_stat[dir][ecn].bytes+=trace_get_wire_length(packet);
	suppress[dir] = false;
}

void ecn_suppress()
{
	int i;
	printf("%-20s","Direction:");
	//printf("%20s", " ");
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
	printf("%-20s","ECN");
	for(i=0;i<4;i++){
		if(!suppress[i]){
			printf("\t%12s\t%12s", "bytes","packets");
		}
	}
	printf("\n");
}

void ecn_report(void)
{
	int i,j;
	printf("# ECN breakdown:\n");
	ecn_suppress();
	for(i=0;i<4;++i) {
		if (ecn_stat[0][i].count==0 && 
			ecn_stat[1][i].count==0 && ecn_stat[2][i].count==0)
			continue;
		printf("%20i:",i);
		for(j=0;j<4;j++){
			if (ecn_stat[j][i].count==0){
				if(!suppress[j])
					printf("\t%24s"," ");
				continue;
			}
			printf("\t%12" PRIu64 "\t%12" PRIu64,
				ecn_stat[j][i].bytes,
				ecn_stat[j][i].count);
		}
		printf("\n");
	}
	
	int total = 0;
	for(i=0;i<4;i++){
		for(j=1;j<4;j++)
			total += ecn_stat[i][j].count;
	}
	printf("%s: %i\n", "Total ECN", total);
}
