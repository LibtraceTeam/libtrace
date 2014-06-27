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

#include "libtrace.h"

struct libtrace_t *trace;

void iferr(libtrace_t *trace)
{
	libtrace_err_t err = trace_get_err(trace);
	if (err.err_num==0)
		return;
	printf("Error: %s\n",err.problem);
	exit(1);
}

int main(int argc, char *argv[]) {
        char *uri = "pcap:traces/100_packets.pcap";
	int error = 0;
	int srccount = 0;
        int dstcount = 0;
	int count = 0;
        int psize = 0;
        struct libtrace_packet_t *packet;

	trace = trace_create(uri);
	iferr(trace);

	if (trace_start(trace)==-1) {
		iferr(trace);
	}
	
	packet=trace_create_packet();
        for (;;) {
		if ((psize = trace_read_packet(trace, packet)) <=0) {
			if (psize != 0) error = 1;
			break;
		}
		if (psize == 0) {
			error = 0;
			break;
		}
	
                if (trace_get_source_port(packet) == 80) {
                        srccount ++;
                }
                if (trace_get_destination_port(packet) == 53) {
                        dstcount ++;
                }
        	
		count ++;
        }
	trace_destroy_packet(packet);
	if (error == 0) {
		if (count == 100) {
			printf("success: 100 packets read\n");
		} else {
			printf("fail: 100 packets expected, %d seen\n",count);
			error = 1;
		}

                if (srccount == 27) {
                        printf("success: 27 src port 80 packets observed\n");
                } else {
                        printf("fail: 27 src port 80 packets expected, %u seen\n", srccount);
                        error = 1;
                }

                if (dstcount == 5) {
                        printf("success: 5 dst port 53 packets observed\n");
                } else {
                        printf("fail: 5 dst port 53 packets expected, %u seen\n", dstcount);
                        error = 1;
                }

	} else {
		iferr(trace);
	}
        trace_destroy(trace);
        return error;
}
