// $Id$

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

struct timeval current,last,diff,total;

void alarmsig(int sig) {
        docalc++;
}

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

        char *hostname = "rtclient:chasm.cs.waikato.ac.nz";
        int psize = 0;
        int status = 0;
        struct sigaction sigact;
        struct libtrace_ip *ipptr = 0;

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
                hostname = strdup(argv[1]);
        }

        // create an trace to hostname, on the default port
        trace = create_trace(hostname);


        for (;;) {
                if ((psize = libtrace_read_packet(trace, buffer,SCANSIZE, &status)) == -1) {
                        // terminate
                        break;
                }
                if (psize == 0) {
                        continue;
                }

                //erfptr = (dag_record_t *)buffer;
                //ipptr = (struct ip *)erfptr->rec.eth.pload;
                if((ipptr = get_ip(trace,buffer,SCANSIZE)) == 0) {
			continue;
		}
		
                counter[BYTES][INSTANT] += ntohs(ipptr->ip_len);
                counter[PACKETS][INSTANT] ++;

                if(docalc) {
                        secondreport();
                }


        }

        destroy_trace(trace);
        return 0;
}
