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

void protocol_suppress()
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
	printf("%-20s","Protocol");
	for(i=0;i<3;i++){
		if(!suppress[i]){
			printf("\t%12s\t%12s", "bytes","packets");
		}
	}
	printf("\n");
}

void protocol_report(void)
{
	int i,j;
	printf("# Protocol breakdown:\n");
	protocol_suppress();
	setprotoent(1);
	for(i=0;i<256;++i) {
		struct protoent *prot;
		if (prot_stat[0][i].count==0 && 
			prot_stat[1][i].count==0 && prot_stat[2][i].count==0)
			continue;
		prot = getprotobynumber(i);
		if (prot) {
			printf("%20s",prot->p_name);
			for(j=0;j<3;j++){
				if (prot_stat[j][i].count==0){
					if(!suppress[j])
						printf("\t%24s"," ");
					continue;
				}
				printf("\t%12" PRIu64 "\t%12" PRIu64,
						prot_stat[j][i].bytes,
						prot_stat[j][i].count);
			}
		}
		else {
			printf("%20i:",i);
			for(j=0;j<3;j++){
				if (prot_stat[j][i].count==0){
					if(!suppress[j])
						printf("\t%24s"," ");
					continue;
				}
				printf("\t%12" PRIu64 "\t%12" PRIu64,
						prot_stat[j][i].bytes,
						prot_stat[j][i].count);
			}
		}
		printf("\n");
	}
	setprotoent(0);
}
