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
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/time.h>
#include <inttypes.h>
#include "libtrace.h"
#include "dagformat.h"

struct libtrace_t *trace;

#define SCANSIZE 4096

#define ALPHA 0.9

char *buffer[SCANSIZE];

static int docalc = 0;

typedef enum counter_type {
        BYTES = 0,
        PACKETS = 1
} counter_type_t;

typedef enum counter_frame {
        INSTANT = 0,
        SMOOTHED = 1
} counter_frame_t;

#define MAXCOUNTERTYPE (PACKETS + 1)
#define MAXCOUNTERFRAME (SMOOTHED + 1)

int32_t counter[MAXCOUNTERTYPE][MAXCOUNTERFRAME];

int32_t event_read_packet(struct libtrace_t *trace, struct libtrace_packet_t *packet);

struct timeval current,last,diff,total;

void secondreport() {

        static int hdrcount = 10;

        if (hdrcount >= 10) {
                printf("Byte count: smoothed[instant]       Packet count: smoothed[instant]\n");
                hdrcount = 0;
        }
        hdrcount++;
        counter[BYTES][SMOOTHED] = ALPHA * counter[BYTES][SMOOTHED] + (1 - ALPHA) * counter[BYTES][INSTANT];
        counter[PACKETS][SMOOTHED] = ALPHA * counter[PACKETS][SMOOTHED] + (1 - ALPHA) * counter[PACKETS][INSTANT];

        printf("\t\t%d[%d]\t\t\t%d[%d] \n", 
                        counter[BYTES][SMOOTHED], 
                        counter[BYTES][INSTANT],
                        counter[PACKETS][SMOOTHED],
                        counter[PACKETS][INSTANT]);
        counter[BYTES][INSTANT] = 0;
        counter[PACKETS][INSTANT] = 0;
        docalc=0;
}
int main(int argc, char *argv[]) {

        char *uri = 0;
        int psize = 0;
        struct libtrace_ip *ipptr = 0;
	struct libtrace_packet_t packet;
	uint32_t last_second = 0;
	double ts = 0.0;


        if (argc == 2) {
                uri = strdup(argv[1]);
        }

        // create an trace to uri
        trace = trace_create(uri);

	if(!trace) {
		trace_perror("trace_create");
		//fprintf(stderr,"Bad trace, check your input uri (%s)\n",uri);
		exit(0);
	}


        for (;;) {
		if ((psize = event_read_packet(trace,&packet)) < 0) {
			break;
		}
		if (psize == 0) {
			continue;
		}

                if((ipptr = trace_get_ip(&packet)) == 0) {
			continue;
		}
		
                counter[BYTES][INSTANT] += ntohs(ipptr->ip_len);
                counter[PACKETS][INSTANT] ++;

		ts = trace_get_seconds(&packet);
		if(last_second == 0) {
			last_second = (int)ts;
		} else if (last_second < (int)ts) {
			last_second = (int)ts;
			docalc++;
		}

                if(docalc) {
                        secondreport();
                }


        }
        trace_destroy(trace);
        return 0;
}


int32_t event_read_packet(struct libtrace_t *trace, struct libtrace_packet_t *packet) {
	struct libtrace_eventobj_t obj;
	struct timeval etv;
	int32_t sleepusec = 0;
	fd_set rfds;

	FD_ZERO(&rfds);

	for (;;) {
		obj = trace_event(trace,packet);
		if (obj.size <= 0) {
			return obj.size;
		}
		if (obj.type == TRACE_EVENT_IOWAIT) {
			// select() on fd
			FD_ZERO(&rfds);
			FD_SET(obj.fd,&rfds);
			select(obj.fd + 1, &rfds,NULL,NULL,0);
			continue;
		} else if (obj.type == TRACE_EVENT_SLEEP) {
			// sleep on seconds
			// Use select for better precision.
			etv.tv_sec = (int) obj.seconds;
			etv.tv_usec = (int) ((obj.seconds - etv.tv_sec) * 1000000.0);
			select(0,NULL,NULL,NULL,&etv);
			continue;
		} else if (obj.type == TRACE_EVENT_PACKET) {
			return packet->size;
		} else {
			fprintf(stderr,"Unknown event type %d\n",obj.type);
			return -1;
		}
	}

}
