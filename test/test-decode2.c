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

int main(int argc, char *argv[]) {
	int psize = 0;
	int error = 0;
	int count = 0;
	int level = 0;
	int ipcnt = 0;
	int expected = 100;
	libtrace_t *trace;
	libtrace_packet_t *packet;

	if (argc<2) {
		fprintf(stderr,"usage: %s uri\n",argv[0]);
		return 1;
	}

	trace = trace_create(argv[1]);
	iferr(trace);

	if (strcmp(argv[1],"rtclient")==0) expected=101;
	
	level=0;

	trace_start(trace);
	iferr(trace);
	
	packet=trace_create_packet();
	for (;;) {
		if ((psize = trace_read_packet(trace, packet)) <0) {
			error = 1;
			iferr(trace);
			break;
		}
		if (psize == 0) {
			error = 0;
			break;
		}

		if ((trace_get_ip(packet)!=NULL)) {
			++ipcnt;
		}
		count ++;
		if (count>100)
			break;
        }
	trace_destroy_packet(packet);
	if (ipcnt==0) {
		error=1;
		printf("No IP packets found!\n");
	}
        trace_destroy(trace);
        return error;
}
