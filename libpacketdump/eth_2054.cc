/* ARP */
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libpacketdump.h"
#include <sys/socket.h>
#ifndef WIN32
	#include <netinet/in_systm.h>
#endif
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <string.h>

#define DISPLAY_EXP(x,fmt,exp) \
	if ((unsigned int)len>=((char*)&ip->x-(char*)ip+sizeof(ip->x))) \
		printf(fmt,exp); \
	else \
		return; 

#define DISPLAY(x,fmt) DISPLAY_EXP(x,fmt,ip->x)

#define DISPLAYS(x,fmt) DISPLAY_EXP(x,fmt,htons(ip->x))
#define DISPLAYIP(x,fmt) DISPLAY_EXP(x,fmt,inet_ntoa(*(struct in_addr*)&ip->x))

static char *format(struct arphdr *arp, char *hrd, char *pro)
{
	static char buffer[1024];
	char ether_buf[18] = {0, };
	if (hrd==NULL)
		return "Truncated (Truncated)";
	switch(arp->ar_hrd) {
		case ARPHRD_ETHER:
			strcpy(buffer,trace_ether_ntoa((uint8_t *)&hrd, 
						ether_buf));
			break;
		default:
			int i;
			for (i=0;i<arp->ar_hln;i++) {
				snprintf(buffer,sizeof(buffer),"%s %02x",
						buffer,(unsigned char)hrd[i]);
			}
	}
	if (pro==NULL) {
		strncat(buffer," (Truncated)",sizeof(buffer));
		return buffer;
	}
	switch(arp->ar_pro) {
		case 0x0800:
			snprintf(buffer,sizeof(buffer),"%s (%s)",
					buffer,inet_ntoa(*(struct in_addr*)&pro));
			break;
		default:
			int i;
			strncat(buffer," (",sizeof(buffer));
			for (i=0;i<arp->ar_pln;i++) {
				snprintf(buffer,sizeof(buffer),"%s %02x",
						buffer,(unsigned char)pro[i]);
			}
			strncat(buffer,")",sizeof(buffer));
			break;
	}
	return buffer;
}

extern "C"
void decode(int link_type,char *packet,int len)
{
	struct arphdr *arp = (struct arphdr*)packet;
	char *source_hrd = NULL;
	char *source_pro = NULL;
	char *dest_hrd = NULL;
	char *dest_pro = NULL;
	if (len<8)
		return;
	if (sizeof(*arp)<=(unsigned int)len) 
		source_hrd=packet+sizeof(arp);
	if (source_hrd && source_hrd-packet+arp->ar_hln<=len)
		source_pro =source_hrd+arp->ar_hln;
	if (source_pro  && source_pro-packet+arp->ar_pln<=len)
		dest_hrd  =source_pro +arp->ar_pln;
	if (dest_hrd   && dest_hrd-packet+arp->ar_pln<=len)
		dest_pro   =dest_hrd  +arp->ar_hln;
	switch(arp->ar_op) {
		case ARPOP_REQUEST:
			printf(" ARP: Who-has %s",
					format(arp,source_hrd,source_pro));
			printf(" please tell %s",
					format(arp,dest_hrd,dest_pro));
			break;
		default:
			printf(" ARP: Unknown opcode (%i) from %s",
					arp->ar_op,
					format(arp,source_hrd,source_pro));
			printf(" to %s",
					format(arp,dest_hrd,dest_pro));
			break;
	}
	return;
}
