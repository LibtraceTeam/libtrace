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

#define SCANSIZE 4096

#define ALPHA 0.9

char *buffer[SCANSIZE];

static int docalc = 0;

typedef enum counter_dir {
        OUT = 0,
        IN = 1,
        NEITHER = 2,
        ERK = 3
} counter_dir_t;

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
#define MAXCOUNTERDIR (ERK + 1)
int32_t counter[MAXCOUNTERDIR][MAXCOUNTERTYPE][MAXCOUNTERFRAME];

struct timeval current,last,diff,total;

void alarmsig(int sig) {
        docalc++;
}

static int32_t smoothed(int32_t smoothed, int32_t instant, int32_t alpha) {
        return alpha * smoothed + (1-alpha) * instant;
}

void secondreport() {
        int i;
        static int hdrcount = 10;

        if (hdrcount >= 10) {
                printf("\tOUT\t\t\tIN\t\t\tOTHER\n");
                printf("Bps\tpps\t\tBps\tpps\t\tBps\tpps\n");
                hdrcount = 0;
        }
        hdrcount++;

        for (i = 0; i < MAXCOUNTERDIR; i ++) {
                counter[i][BYTES][SMOOTHED] = smoothed(counter[i][BYTES][SMOOTHED],counter[i][BYTES][INSTANT],ALPHA);
                counter[i][PACKETS][SMOOTHED] = smoothed(counter[i][PACKETS][SMOOTHED],counter[i][PACKETS][INSTANT],ALPHA);
        }
        for (i = 0; i < 2; i++) {
                printf("%d\t%d\t\t",
                                counter[i][BYTES][SMOOTHED], 
                                counter[i][PACKETS][SMOOTHED]);
                counter[i][BYTES][INSTANT] = 0;
                counter[i][PACKETS][INSTANT] = 0;
        }
        printf("%d\t%d\t\t",
                        counter[2][BYTES][INSTANT],
                        counter[2][PACKETS][INSTANT]);
        counter[2][BYTES][INSTANT] = 0;
        counter[2][PACKETS][INSTANT] = 0;
        printf("\n");

        docalc=0;
}
int main(int argc, char *argv[]) {

	char *uri = 0;
        int psize = 0;
	int direction = 0;
        struct sigaction sigact;
        struct libtrace_ip *ipptr = 0;
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

                if((ipptr = trace_get_ip(&packet)) == 0) {
			continue;
		}

		direction = trace_get_direction(&packet);

                counter[direction][BYTES][INSTANT] += ntohs(ipptr->ip_len);
                counter[direction][PACKETS][INSTANT] ++;

                if(docalc) {
                        secondreport();
                }


        }

        trace_destroy(trace);
        return 0;
}
