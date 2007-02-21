#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"

static stat_t tcpopt_stat[4][256] = {{{0,0}}};
static bool suppress[4] = {true,true,true,true};

void tcpopt_per_packet(struct libtrace_packet_t *packet)
{
	unsigned char *p=trace_get_link(packet);
	struct libtrace_tcp *tcp = trace_get_tcp(packet);
	
	if(!tcp)
		return;
	
	int dir = trace_get_direction(packet);
	if(dir < 0 || dir > 1)
		dir = 2;
	
	int len = trace_get_capture_length(packet) - 54;
	if(len == 0)
		return;
	
	int tcp_bytes = trace_get_wire_length(packet) - trace_get_capture_length(packet);
	int i = tcp->doff*4 - sizeof *tcp;
	
	if(len > i)
		len = i;
	
	unsigned char type,optlen,*data;
	p += 54; //hax 14 mac header, 20 ip header, 20tcp header
	
	while(trace_get_next_option(&p,&len,&type,&optlen,&data)){
		tcpopt_stat[dir][type].count++;
		tcpopt_stat[dir][type].bytes+= tcp_bytes;
	}
	
	suppress[dir] = false;
}

void tcpopt_suppress()
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
	printf("%-20s","TCP OPTIONS");
	for(i=0;i<4;i++){
		if(!suppress[i]){
			printf("\t%12s\t%12s", "bytes","packets");
		}
	}
	printf("\n");
}

void tcpopt_report(void)
{
	int i,j;
	printf("# TCP OPTION breakdown:\n");
	tcpopt_suppress();
	
	for(i=0;i<256;++i) {
		if (tcpopt_stat[0][i].count==0 && 
			tcpopt_stat[1][i].count==0 && tcpopt_stat[2][i].count==0)
			continue;
		
		switch(i) {
			case 1:
				printf("%20s", "NOP: ");
				break;
			case 2:
				printf("%20s", "MSS: ");
				break;
			case 3:
				printf("%20s", "Winscale: ");
				break;
			case 4:
				printf("%20s", "SACK Permitted: ");
				break;
			case 5:
				printf("%20s", "SACK Information: ");
				break;
			case 8:
				printf("%20s", "Timestamp: ");
				break;
			case 19:
				printf("%20s", "MD5: ");
			default:
				printf("%20i:",i);
		}
		
		for(j=0;j<4;j++){
			if (tcpopt_stat[j][i].count==0){
				if(!suppress[j])
					printf("\t%24s"," ");
				continue;
			}
			printf("\t%12" PRIu64 "\t%12" PRIu64,
				tcpopt_stat[j][i].bytes,
				tcpopt_stat[j][i].count);
		}
		printf("\n");
	}
}
