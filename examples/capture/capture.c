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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdint.h>
#include "libtrace.h"
#include "dagformat.h"

struct libtrace_t *trace;


#define ALPHA 0.9

static int docalc = 0;

typedef enum counter_type {
        BYTES = 0,
        PACKETS = 1,
	LOSS = 2,
} counter_type_t;

#define MAXCOUNTERTYPE (LOSS + 1)

uint32_t counter[MAXCOUNTERTYPE];

struct timeval current,last,diff,total;

void alarmsig(int sig) {
        docalc++;
}

void secondreport() {

        static int hdrcount = 10;

        if (hdrcount >= 10) {
                printf("Byte count: 	Packet count: 		Loss count\n");
                hdrcount = 0;
        }
        hdrcount++;
        printf("\t\t%d\t\t%d\t\t%d \n", 
                        counter[BYTES],
                        counter[PACKETS],
			counter[LOSS]);
        counter[BYTES] = 0;
        counter[PACKETS] = 0;
	counter[LOSS] = 0;
        docalc=0;
}
int main(int argc, char *argv[]) {

        char *uri = 0;
	char *filename = 0;
	FILE *fout = 0;
        int psize = 0;
        struct sigaction sigact;
	dag_record_t *erfptr = 0;
	struct libtrace_packet_t packet;

        struct itimerval itv;

        /* 
         * Set up a timer to expire every second, for reporting
         */
        sigact.sa_handler = alarmsig;
        sigact.sa_flags = SA_RESTART;
        if(sigaction(SIGALRM, &sigact, NULL) < 0)
                perror("sigaction");
        itv.it_interval.tv_sec = 1;
        itv.it_interval.tv_usec = 0;
        itv.it_value.tv_sec = 1;
        itv.it_value.tv_usec = 0;
        if (setitimer(ITIMER_REAL, &itv, NULL) < 0)
                perror("setitimer");

        if (argc == 2) {
                uri = strdup(argv[1]);
		filename = 0;
        }

        if (argc == 3) {
                uri = strdup(argv[1]);
		filename = strdup(argv[2]);
		fout = fopen(filename,"w");
        }
	
        // create an trace to uri
        trace = trace_create(uri);


        for (;;) {
                if ((psize = trace_read_packet(trace,&packet)) == -1) {
                        // terminate
                        break;
                }
                if (psize == 0) {
                        continue;
                }

		erfptr = (dag_record_t *)(&packet.buffer);

                counter[BYTES] += ntohs(erfptr->rlen);
                counter[PACKETS] ++;
		counter[LOSS] += ntohs(erfptr->lctr);

                if(docalc) {
                        secondreport();
                }
		
		if (filename) 
			fwrite(erfptr,psize,1,fout);


        }

        trace_destroy(trace);
	fclose(fout);
        return 0;
}
