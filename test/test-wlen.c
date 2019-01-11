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
 * $Id: test-rtclient.c,v 1.2 2006/02/27 03:41:12 perry Exp $
 *
 */
#ifndef WIN32
#  include <sys/time.h>
#  include <netinet/in.h>
#  include <netinet/in_systm.h>
#  include <netinet/tcp.h>
#  include <netinet/ip.h>
#  include <netinet/ip_icmp.h>
#  include <arpa/inet.h>
#  include <sys/socket.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>

#include "dagformat.h"
#include "libtrace.h"
#include "libpacketdump.h"

void iferr(libtrace_t *trace)
{
	libtrace_err_t err = trace_get_err(trace);
	if (err.err_num==0)
		return;
	printf("Error: %s\n",err.problem);
	exit(1);
}

const char *lookup_uri(const char *type) {
	if (strchr(type,':') || strchr(type,'/'))
		return type;
	if (!strcmp(type,"erf"))
		return "erf:traces/100_packets.erf";
	if (!strcmp(type,"rawerf"))
		return "rawerf:traces/100_packets.erf";
	if (!strcmp(type,"pcap"))
		return "pcap:traces/100_packets.pcap";
	if (!strcmp(type,"pcapng"))
		return "pcap:traces/100_packets.pcapng";
	if (!strcmp(type,"pcapfile"))
		return "pcapfile:traces/100_packets.pcap";
	if (!strcmp(type,"pcapfilens"))
		return "pcapfile:traces/100_packetsns.pcap";
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

int get_expected_wlen(const char *type) {
	if (!strcmp(type,"erf"))
		return 30960;
	if (!strcmp(type,"rawerf"))
		return 30960;
	if (!strcmp(type,"pcap"))
                return 31360;
	if (!strcmp(type,"pcapng"))
                return 31360;
	if (!strcmp(type,"pcapfile"))
                return 31360;
	if (!strcmp(type,"pcapfilens"))
                return 31360;
	if (!strcmp(type, "legacyatm"))
		return 5300;
	if (!strcmp(type, "legacypos"))
                return 57456;
	if (!strcmp(type, "legacyeth"))
	        return 30372;
        if (!strcmp(type, "tsh"))
		return 67341;
        return 0;
}

int main(int argc, char *argv[]) {
	int psize = 0;
	int error = 0;
	int count = 0;
	int expected = 100;
        size_t expectedwlen = 0;
        size_t totalwlen = 0;
	libtrace_t *trace;
	libtrace_packet_t *packet;

	if (argc<2) {
		fprintf(stderr,"usage: %s type\n",argv[0]);
		return 1;
	}

	trace = trace_create(lookup_uri(argv[1]));
	iferr(trace);

	trace_start(trace);
	iferr(trace);

        expectedwlen = get_expected_wlen(argv[1]);

	packet=trace_create_packet();
	for (;;) {
                size_t wlen;
		if ((psize = trace_read_packet(trace, packet)) <0) {
			error = 1;
			iferr(trace);
			break;
		}
		if (psize == 0) {
			error = 0;
			break;
		}
                
                if ((wlen = trace_get_wire_length(packet)) <= 0) {
                        error = 0;
                        break;
                }

		count ++;
                totalwlen += wlen;
		if (count>100)
			break;
        }
	trace_destroy_packet(packet);
	if (error == 0) {
		if (count == expected) {
			printf("success: %d packets read\n",expected);
		} else {
			printf("failure: %d packets expected, %d seen\n",expected,count);
			error = 1;
		}
                if (totalwlen == expectedwlen) {
			printf("success: %zu wire bytes read\n",expectedwlen);
		} else {
			printf("failure: %zu wire bytes expected, %zu seen\n",expectedwlen,totalwlen);
			error = 1;
		}

	} else {
		iferr(trace);
	}
        trace_destroy(trace);
        return error;
}
