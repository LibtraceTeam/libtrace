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

#include <stdio.h> /* printf */
#include <netinet/in.h> /* ntohs */
#include <netdb.h>
#include "dagformat.h"

#include "libtrace.h"

struct libtrace_t *trace;

char *buffer[4096];

int main(int argc, char *argv[]) {

        char *hostname = "rtclient:chasm.cs.waikato.ac.nz";
	char *filterstring = 0;
	struct libtrace_ip *ipptr = 0;
	
        int status; // need to pass to rtclient_read_packet
        int psize;
        if (argc == 2) {
                hostname = argv[1];
        }
	if (argc == 3) {
		hostname = argv[1];
		filterstring = argv[2];
	}

        // create an rtclient to hostname, on the default port
        trace = create_trace(hostname);
	if (filterstring) {
		libtrace_bpf_setfilter(trace,filterstring);
	}

        for (;;) {
                if ((psize = libtrace_read_packet(trace, buffer,4096, &status)) <= 0) {
                        // terminate
                        break;
                }
		if (!libtrace_bpf_filter(trace, buffer, 4096)) {
			continue;
		}
	 	ipptr = get_ip(trace,buffer,4096);
		if (ipptr) {
			printf("%d:%d\n",ipptr->ip_p,get_link_type(trace,buffer,4096));
		}
        }
        destroy_trace(trace);
        return 0;
}
