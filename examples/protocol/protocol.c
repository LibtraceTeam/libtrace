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
