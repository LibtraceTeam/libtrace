// $Id$
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

        char *uri = "rtclient:chasm.cs.waikato.ac.nz";
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
