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
#include <getopt.h>
#include <inttypes.h>
#include <sys/resource.h>
#include <unistd.h>

#include "libtrace.h"

struct libtrace_t *trace;


uint64_t tot=0;
/* Process a trace, counting packets that match filter(s) */
void run_trace(char *uri) 
{
	struct libtrace_packet_t *packet = trace_packet_create();
	uint64_t count = 0;
	uint64_t bytes = 0;
	uint64_t nontcp_count = 0;
	uint64_t nontcp_bytes = 0;



        trace = trace_create(uri);

        for (;;) {
		int psize;
                if ((psize = trace_read_packet(trace, &packet)) <1) {
                        break;
                }

		if (trace_get_tcp(&packet)) {
			++nontcp_count;
			nontcp_bytes+=trace_get_wire_length(&packet);
		}

		++count;
		bytes+=trace_get_wire_length(&packet);
		++tot;
        }


        trace_destroy(trace);
}

#define TIMER_SUB(res,a,b)				\
	do {						\
		res.tv_sec = a.tv_sec - b.tv_sec;	\
		res.tv_usec = a.tv_usec - b.tv_usec;    \
		if (res.tv_usec < 0) {                	\
			--res.tv_sec;                   \
			res.tv_usec += 1000000; 	\
		}                                       \
	} while(0)

int main(int argc, char *argv[]) {

	int i;
	struct timeval start,end;
	struct timeval interval;
	struct rusage start_usage,end_usage;

	getrusage(RUSAGE_SELF,&start_usage);
	gettimeofday(&start,NULL);
	for(i=optind;i<argc;++i) {
		run_trace(argv[i]);
	}
	gettimeofday(&end,NULL);
	getrusage(RUSAGE_SELF,&end_usage);

	TIMER_SUB(interval,end,start);

	printf("Tracemarks: %.02f\n",((double)tot)/(interval.tv_sec+interval.tv_usec/100000));

	printf("Real: %i.%05is\n",interval.tv_sec,interval.tv_usec);
	TIMER_SUB(interval,end_usage.ru_utime,start_usage.ru_utime);
	printf("User: %i.%05is\n",interval.tv_sec,interval.tv_usec);
	TIMER_SUB(interval,end_usage.ru_stime,start_usage.ru_stime);
	printf("System: %i.%06is\n",interval.tv_sec,interval.tv_usec);
	printf("I/O: %li/%li\n",end_usage.ru_inblock-start_usage.ru_inblock,
				end_usage.ru_oublock-start_usage.ru_oublock);
        return 0;
}
