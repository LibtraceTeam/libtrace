/*
 * This file is part of libtrace
 *
 * Copyright (c) 2004 The University of Waikato, Hamilton, New Zealand.
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

// 
// This program takes a trace and outputs every packet that it sees to standard
// out, decoding source/dest IP's, protocol type, and the timestamp of this
// packet.

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "dagformat.h"
#include "libtrace.h"

struct libtrace_t *trace;

#define SCANSIZE 4096

char *buffer[SCANSIZE];

int main(int argc, char *argv[]) {

        char *uri = 0;
        int psize = 0;
        int status = 0;
        struct libtrace_ip *ipptr = 0;

        if (argc == 2) {
                uri = strdup(argv[1]);
        }

        // open a trace
        trace = create_trace(uri);

        for (;;) {
		unsigned char *x;
		int i;
                if ((psize = libtrace_read_packet(trace, buffer, SCANSIZE, &status)) <1) {
                        break;
                }

		printf("TS %f: ",get_seconds(trace,buffer,SCANSIZE));

                ipptr = get_ip(trace,buffer,SCANSIZE);
		if (!ipptr) {
			printf("Non IP\n");
			continue;
		}

		printf("%s -> ",inet_ntoa(ipptr->ip_src));
		printf("%s protocol %02x\n",
					inet_ntoa(ipptr->ip_dst),
					ipptr->ip_p);
		x=(void*)ipptr;
		for(i=0;i<get_capture_length(trace,buffer,SCANSIZE);i++) {
			if (i%4==0 && i!=0)
				printf("\n");
			printf("%02x ",x[i]);
		}
		printf("\n\n");
        }

        destroy_trace(trace);
        return 0;
}
