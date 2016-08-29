/*
 *
 * Copyright (c) 2007-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libpacketdump.h"
#include <assert.h>
#include <netdb.h>

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	unsigned char *pkt = NULL;
	unsigned char type,optlen,*data;
	int plen, i;
	libtrace_tcp_t *tcp = (libtrace_tcp_t *)packet;
	printf(" TCP:");
	if (SAFE(tcp, source)) {
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
	if (SAFE(tcp, dest)) {
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
	DISPLAYL(tcp, seq," Seq %u");
	printf("\n TCP:");
	DISPLAYL(tcp, ack_seq," Ack %u");
	if ((char*)&tcp->window-(char *)tcp>len) {
		printf("\n");
		return;
	}
	printf("\n TCP:");
	printf(" DOFF %i",tcp->doff);
	printf(" Flags:");
	if (tcp->ecn_ns) printf(" ECN_NS");
	if (tcp->cwr) printf(" CWR");
	if (tcp->ece) printf(" ECE");
	if (tcp->fin) printf(" FIN");
	if (tcp->syn) printf(" SYN");
	if (tcp->rst) printf(" RST");
	if (tcp->psh) printf(" PSH");
	if (tcp->ack) printf(" ACK");
	if (tcp->urg) printf(" URG");
	DISPLAYS(tcp, window," Window %i");
	printf("\n TCP:");
	DISPLAYS(tcp, check," Checksum %i");
	DISPLAYS(tcp, urg_ptr," Urgent %i");
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
