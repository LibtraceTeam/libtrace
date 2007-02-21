#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"

static stat_t nlp_stat[4][65536] = {{{0,0}}} ;
static bool suppress[4] = {true,true,true,true};

void nlp_per_packet(struct libtrace_packet_t *packet)
{
	unsigned char *p=trace_get_link(packet);
	uint16_t a;
	
	p += 12;
	a = *p;
	a *= 256;
	a += p[1];
	int dir = trace_get_direction(packet);
	if(dir < 0 || dir > 1)
		dir = 2;
	
	nlp_stat[dir][a].count++;
	nlp_stat[dir][a].bytes+=trace_get_wire_length(packet);
	suppress[dir] = false;
}

void nlp_suppress()
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
	printf("%-20s","NLP");
	for(i=0;i<4;i++){
		if(!suppress[i]){
			printf("\t%12s\t%12s", "bytes","packets");
		}
	}
	printf("\n");
}

void nlp_report(void){
	printf("# Network Layer Protocol breakdown:\n");
	nlp_suppress();
	int i,j;
	
	for(i = 0; i < 65536; i++){
		if (nlp_stat[0][i].count==0 && 
			nlp_stat[1][i].count==0 && nlp_stat[2][i].count==0)
			continue;
		switch(i){
			case 0x0800: 
				printf("%20s", "IPv4");
				break;
			case 0x0806: 
				printf("%20s", "ARP");
				break;
			case 0x8137:	
				printf("%20s", "IPX");
				break;
			case 0x814C:
				printf("%20s", "SNMP");
				break;
			case 0x86DD:
				printf("%20s", "IPv6");
				break;
			case 0x880B:
				printf("%20s", "PPP");
				break;
			default:
				printf("%20i:",i);
		}
		for(j=0;j<4;j++){
			if (nlp_stat[j][i].count==0){
				if(!suppress[j])
					printf("\t%24s"," ");
				continue;
			}
			printf("\t%12" PRIu64 "\t%12" PRIu64,
				nlp_stat[j][i].bytes,
				nlp_stat[j][i].count);
		}
		printf("\n");
	}
}
