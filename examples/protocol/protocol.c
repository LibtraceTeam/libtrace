// $Id$

#include <stdio.h> /* printf */
#include <netinet/in.h> /* ntohs */
#include <netdb.h>
#include "dagformat.h"

#include "libtrace.h"

struct libtrace_t *trace;

char *buffer[4096];

int main(int argc, char *argv[]) {

        char *hostname = "rtclient:chasm.cs.waikato.ac.nz";
	struct libtrace_ip *ipptr = 0;
	
        int status; // need to pass to rtclient_read_packet
        int psize;
        if (argc == 2) {
                hostname = argv[1];
        }

        // create an rtclient to hostname, on the default port
        trace = create_trace(hostname);

        for (;;) {
                if ((psize = libtrace_read_packet(trace, buffer,4096, &status)) <= 0) {
                        // terminate
                        break;
                }
	 	ipptr = get_ip(trace,buffer,4096);
		if (ipptr) {
			printf("%d\n",ipptr->ip_p);
		}
        }
        destroy_trace(trace);
        return 0;
}
