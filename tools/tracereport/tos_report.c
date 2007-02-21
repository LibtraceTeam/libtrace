#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"

static stat_t tos_stat[4][256] = {{{0,0}}} ;
static bool suppress[4] = {true,true,true,true};

void tos_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_ip *ip = trace_get_ip(packet);
	
	if (!ip)
		return;
	int dir = trace_get_direction(packet);
	if(dir < 0 || dir > 1)
		dir = 2;
	tos_stat[dir][ip->ip_tos].count++;
	tos_stat[dir][ip->ip_tos].bytes+=trace_get_wire_length(packet);
	suppress[dir] = false;
}

void tos_suppress()
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
	printf("%-20s","ToS");
	for(i=0;i<4;i++){
		if(!suppress[i]){
			printf("\t%12s\t%12s", "bytes","packets");
		}
	}
	printf("\n");
}

void tos_report(void)
{
	int i,j;
	printf("# TOS breakdown:\n");
	tos_suppress();
	for(i=0;i<256;++i) {
		if (tos_stat[0][i].count==0 && 
			tos_stat[1][i].count==0 && tos_stat[2][i].count==0)
			continue;
		printf("%20i:",i);
		for(j=0;j<4;j++){
			if (tos_stat[j][i].count==0){
				if(!suppress[j])
					printf("\t%24s"," ");
				continue;
			}
			printf("\t%12" PRIu64 "\t%12" PRIu64,
				tos_stat[j][i].bytes,
				tos_stat[j][i].count);
		}
		printf("\n");
	}
	
	int total;
	for(i=0;i<4;i++){
		total = 0;
		for(j=0;j<256;j++)
			total += tos_stat[i][j].count;
		//printf("%s: %i\n", "Total", total);
	}
}
