#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
#include <map>
#include "tracedump.h"
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <assert.h>

#define SAFE(x) \
	((unsigned int)len>=((char*)&tcp->x-(char*)tcp+sizeof(tcp->x))) 
#define DISPLAY_EXP(x,fmt,exp) \
	if (SAFE(x)) \
		printf(fmt,exp); \
	else \
		return; 

#define DISPLAY(x,fmt) DISPLAY_EXP(x,fmt,tcp->x)

#define DISPLAYS(x,fmt) DISPLAY_EXP(x,fmt,htons(tcp->x))
#define DISPLAYL(x,fmt) DISPLAY_EXP(x,fmt,htonl(tcp->x))
#define DISPLAYIP(x,fmt) DISPLAY_EXP(x,fmt,inet_ntoa(*(struct in_addr*)&tcp->x))

int get_next_option(unsigned char **ptr,int *len,
			unsigned char *type,
			unsigned char *optlen,
			unsigned char **data)
{
	if (*len<=0)
		return 0;
	*type=**ptr;
	switch(*type) {
		case 0:
			return 0;
		case 1:
			(*ptr)++;
			(*len)--;
			return 1;
		default:
			*optlen = *(*ptr+1);
			assert(*optlen>=2);
			(*len)-=*optlen;
			(*data)=(*ptr+2);
			(*ptr)+=*optlen+2;
			if (*len<0)
				return 0;
			return 1;
	}
}

extern "C"
void decode(int link_type,char *packet,int len)
{
	struct tcphdr *tcp = (struct tcphdr*)packet;
	printf(" TCP:");
	DISPLAYS(source," Source %i")
	DISPLAYS(dest," Dest %i")
	printf("\n TCP:");
	DISPLAYL(seq," Seq %u");
	printf("\n TCP:");
	DISPLAYL(ack_seq," Ack %u");
	if ((char*)&tcp->window-(char *)tcp>len) {
		printf("\n");
		return;
	}
	printf("\n TCP:");
	printf(" DOFF %i",tcp->doff);
	printf(" Flags:");
	if (tcp->fin) printf(" FIN");
	if (tcp->syn) printf(" SYN");
	if (tcp->rst) printf(" RST");
	if (tcp->psh) printf(" PSH");
	if (tcp->ack) printf(" ACK");
	if (tcp->urg) printf(" URG");
	DISPLAYS(window," Window %i");
	printf("\n TCP:");
	DISPLAYS(check," Checksum %i");
	DISPLAYS(urg_ptr," Urgent %i");
	unsigned char *pkt = (unsigned char*)packet+sizeof(*tcp);
	int plen = (len-sizeof *tcp) <? (tcp->doff*4-sizeof *tcp);
	unsigned char type,optlen,*data;
	while(get_next_option(&pkt,&plen,&type,&optlen,&data)) {
		printf("\n TCP: ");
		switch(type) {
			case 0:
				printf("End of options");
				break;
			case 1:
				printf("NOP");
				break;
			case 2:
				printf("MSS %i",htons(*(uint32_t *)(data)));
				break;
			case 3:
				printf("Winscale %i",data[0]);
				break;
			case 4:
				printf("SACK");
				break;
			case 5:
				printf("SACK Information");
				int i;
				i=0;
				while(i+8<optlen) {
					printf("\n TCP:  %u-%u",
						htonl(*(uint32_t*)&data[i]),
						htonl(*(uint32_t*)&data[i+4]));
					i+=8;
				}
				break;
			case 8:
				printf("Timestamp %u %u",
						htonl(*(uint32_t *)&data[0]),
						htonl(*(uint32_t *)&data[4])
				      );
				break;
			default:
				printf("Unknown option %i",type);
		}
	}
	printf("\n");
	if (htons(tcp->source) < htons(tcp->dest)) 
		decode_next(packet+tcp->doff*4,len-tcp->doff*4,"tcp",htons(tcp->source));
	else
		decode_next(packet+tcp->doff*4,len-tcp->doff*4,"tcp",htons(tcp->dest));
	return;
}
