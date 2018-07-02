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

/* 
 * Converts an ARP hardware address to a printable string.
 * Takes an ARP header structure and a pointer to the start
 * of the hardware address in the structure that we should
 * attempt to decode.
 */
static char *format_hrd(const struct arphdr *arp, const char *hrd) {
	static char buffer[1024] = {0,};
	int i, ret;
        size_t bufused;

	if (!hrd) {
		strncpy(buffer, "(Truncated)", sizeof(buffer));
		return buffer;
	}

	switch(ntohs(arp->ar_hrd)) {
		case ARPHRD_ETHER:
			trace_ether_ntoa((const unsigned char *)hrd, buffer);
			break;
		default:
                        bufused = 0;
			for (i=0;i<arp->ar_hln;i++) {
                                if (bufused >= sizeof(buffer)) {
                                        break;
                                }
                                ret = snprintf(buffer + bufused,
                                                sizeof(buffer) - bufused,
                                                "%02x ",
                                                (unsigned char)hrd[i]);
                                if (ret > 0) {
                                        bufused += ret;
                                }
			}
			break;
	}
	
	return buffer;
}

/* 
 * Converts an ARP protocol address to a printable string.
 * Takes an ARP header structure and a pointer to the start
 * of the protocol address in the structure that we should
 * attempt to decode.
 */
static char *format_pro(const struct arphdr *arp, const char *pro) {
	static char buffer[1024] = {0,};
	int i, ret;
        size_t bufused;
	
	if (!pro) {
		strncpy(buffer, "(Truncated)", sizeof(buffer));
		return buffer;
	}

	switch(ntohs(arp->ar_pro)) {
		case 0x0800:
			snprintf(buffer,sizeof(buffer),"%s",
					inet_ntoa(*(struct in_addr*)pro));
			break;
		default:
			snprintf(buffer, sizeof(buffer), "%s", " (");
                        bufused = 2;
			for (i=0;i<arp->ar_pln;i++) {
                                if (bufused >= sizeof(buffer)) {
                                        break;
                                }
                                ret = snprintf(buffer + bufused,
                                                sizeof(buffer) - bufused,
                                                "%02x ",
                                                (unsigned char)pro[i]);
                                if (ret > 0) {
                                        bufused += ret;
                                }
			}
                        if (bufused < sizeof(buffer)) {
                                snprintf(buffer + bufused,
                                                sizeof(buffer) - bufused,
                                                ")");
                        }
			break;
	}
	return buffer;
	
}
	
DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	struct arphdr *arp = (struct arphdr*)packet;
	const char *source_hrd = NULL;
	const char *source_pro = NULL;
	const char *dest_hrd = NULL;
	const char *dest_pro = NULL;

	if (len < sizeof(struct arphdr)) {
		printf(" ARP: (Truncated)\n");
		return;
	}

	if (len >= sizeof(struct arphdr) + arp->ar_hln) 
		source_hrd = packet + sizeof(struct arphdr);
	if (len >= sizeof(struct arphdr) + arp->ar_hln + arp->ar_pln)
		source_pro = source_hrd + arp->ar_hln;
	if (len >= sizeof(struct arphdr) + arp->ar_hln * 2 + arp->ar_pln)
		dest_hrd = source_pro + arp->ar_pln;
	if (len >= sizeof(struct arphdr) + arp->ar_hln * 2 + arp->ar_pln * 2)
		dest_pro = dest_hrd + arp->ar_hln;

	switch(ntohs(arp->ar_op)) {
		case ARPOP_REQUEST:
			printf(" ARP: who-has %s", format_pro(arp, dest_pro));
			printf(" tell %s (%s)\n", format_pro(arp, source_pro),
					format_hrd(arp, source_hrd));
			break;
		case ARPOP_REPLY:
			printf(" ARP: reply %s", format_pro(arp, source_pro));
			printf(" is-at %s\n", format_hrd(arp, source_hrd));
			break;
		default:
			printf(" ARP: Unknown opcode (%i) from %s to %s\n",
					ntohs(arp->ar_op),
					format_pro(arp, source_pro),
					format_pro(arp, dest_pro));

			break;
	}
	return;
}
