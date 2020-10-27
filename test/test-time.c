/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson 
 *          Perry Lorier 
 *          
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libtrace; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include "dagformat.h"
#include "libtrace.h"

struct libtrace_t *trace;

const char *lookup_uri(const char *type) {
        if (strchr(type,':'))
                return type;
        if (!strcmp(type,"erf"))
                return "erf:traces/100_packets.erf";
        if (!strcmp(type,"rawerf"))
                return "rawerf:traces/100_packets.erf";
        if (!strcmp(type,"pcap"))
                return "pcap:traces/100_packets.pcap";
        if (!strcmp(type,"pcapng"))
                return "pcap:traces/100_packets.pcapng";
        if (!strcmp(type,"wtf"))
                return "wtf:traces/wed.wtf";
        if (!strcmp(type,"rtclient"))
                return "rtclient:chasm";
        if (!strcmp(type,"pcapfile"))
                return "pcapfile:traces/100_packets.pcap";
        if (!strcmp(type,"pcapfilens"))
                return "pcapfile:traces/100_packetsns.pcap";
        if (!strcmp(type, "duck"))
                return "duck:traces/100_packets.duck";
        if (!strcmp(type, "legacyatm"))
                return "legacyatm:traces/legacyatm.gz";
        if (!strcmp(type, "legacypos"))
                return "legacypos:traces/legacypos.gz";
        if (!strcmp(type, "legacyeth"))
                return "legacyeth:traces/legacyeth.gz";
        if (!strcmp(type, "tsh"))
                return "tsh:traces/10_packets.tsh.gz";
        return type;
}

void iferr(libtrace_t *trace)
{
	libtrace_err_t err = trace_get_err(trace);
	if (err.err_num==0)
		return;
	printf("Error: %s\n",err.problem);
	exit(1);
}

int main(int argc, char *argv[]) {
        char *uri = lookup_uri(argv[1]);
        int psize = 0;
	int error = 0;
	int count = 0;
	libtrace_packet_t *packet;

	trace = trace_create(uri);
	iferr(trace);

	trace_start(trace);
	iferr(trace);
	
	packet=trace_create_packet();
        for (;;) {
		double ts;
		double tsdiff;
		struct timeval tv;
		if ((psize = trace_read_packet(trace, packet)) <0) {
			error = 1;
			break;
		}
		if (psize == 0) {
			error = 0;
			break;
		}
		count ++;
		tv=trace_get_timeval(packet);
		ts=trace_get_seconds(packet);
		tsdiff = (tv.tv_sec+tv.tv_usec/1000000.0)-ts;
		assert(tsdiff > -0.001 && tsdiff < 0.001);

        }
	trace_destroy_packet(packet);
	if (error == 0) {
		if (count == 100) {
			printf("success: 100 packets read\n");
		} else {
			printf("failure: 100 packets expected, %d seen\n",count);
			error = 1;
		}
	} else {
		iferr(trace);
	}
        trace_destroy(trace);
        return error;
}
