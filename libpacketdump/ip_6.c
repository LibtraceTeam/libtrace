#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libpacketdump.h"
#include <assert.h>
#include <netdb.h>

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

void decode(int link_type,char *packet,unsigned len)
{
	unsigned char *pkt = NULL;
	unsigned char type,optlen,*data;
	int plen, i;
	libtrace_tcp_t *tcp = (libtrace_tcp_t *)packet;
	printf(" TCP:");
	if (SAFE(source)) {
		struct servent *ent=getservbyport(tcp->source,"tcp");
		if(ent) {
			printf(" Source %i (%s)",htons(tcp->source),ent->s_name);
		} else {
			printf(" Source %i",htons(tcp->source));
		}
	}
	else {
		printf("\n");
		return;
	}
	if (SAFE(dest)) {
		struct servent *ent=getservbyport(tcp->dest,"tcp");
		if(ent) {
			printf(" Dest %i (%s)",htons(tcp->dest),ent->s_name);
		} else {
			printf(" Dest %i",htons(tcp->dest));
		}
	}
	else {
		printf("\n");
		return;
	}
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
	pkt = (unsigned char*)packet+sizeof(*tcp);
	plen = (len-sizeof *tcp) < (tcp->doff*4-sizeof(*tcp))?(len-sizeof(*tcp)):(tcp->doff*4-sizeof *tcp);
	while(trace_get_next_option(&pkt,&plen,&type,&optlen,&data)) {
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
