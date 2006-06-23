/*
 * This file is part of libtrace
 *
 * Copyright (c) 2004 The University of Waikato, Hamilton, New Zealand.
 * Authors: Perry Lorier 
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

char *lookup_out_uri(const char *type) {
	if (!strcmp(type,"erf"))
		return "erf:traces/100_packets.out.erf";
	if (!strcmp(type,"pcap"))
		return "pcap:traces/100_packets.out.pcap";
	if (!strcmp(type,"wtf"))
		return "wtf:traces/wed.out.wtf";
	if (!strcmp(type,"duck"))
		return "duck:traces/100_packets.out.duck";
	return "unknown";
}

void iferr_out(libtrace_out_t *trace)
{
	libtrace_err_t err = trace_get_err_output(trace);
	if (err.err_num==0)
		return;
	printf("Error: %s\n",err.problem);
	exit(1);
}

void iferr(libtrace_t *trace)
{
	libtrace_err_t err = trace_get_err(trace);
	if (err.err_num==0)
		return;
	printf("Error: %s\n",err.problem);
	exit(1);
}

char buffer[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, /* Dest Mac */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x06, /* Src Mac */
		0x01, 0x01, /* Ethertype = Experimental */
		0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, /* payload */
};

int main(int argc, char *argv[]) {
	libtrace_out_t *trace;
	libtrace_packet_t *packet;

	if (argc<2) {
		fprintf(stderr,"usage: %s type\n",argv[0]);
		return 1;
	}

	trace = trace_create_output(lookup_out_uri(argv[1]));
	iferr_out(trace);

	trace_start_output(trace);
	iferr_out(trace);
	
	packet=trace_create_packet();

	trace_construct_packet(packet,TRACE_TYPE_ETH,buffer,sizeof(buffer));

	if (trace_write_packet(trace,packet)==-1) {
		iferr_out(trace);
	}
	trace_destroy_packet(packet);
        trace_destroy_output(trace);
        return 0;
}
