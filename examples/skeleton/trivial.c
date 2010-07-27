/* Trivial libtrace skeleton program
 *
 * This libtrace skeleton has the bare minimum required to write a useful
 * libtrace program, including error handling.
 *
 * If you are going to base your program on anything, you should look at the
 * complete.c and use that.
 *
 */
#include "libtrace.h"
#include <stdio.h>
#include <assert.h>

static void per_packet(libtrace_packet_t *packet)
{
	/* You really should consider using complete.c instead */
	assert(packet);
	
	/* Your code goes here */

}

int main(int argc, char *argv[])
{
	libtrace_t *trace;
	libtrace_packet_t *packet;

	if (argc<2) {
		fprintf(stderr,"usage: %s libtraceuri\n",argv[0]);
		return 1;
	}

	trace = trace_create(argv[1]);

	if (trace_is_err(trace)) {
		trace_perror(trace,"Opening trace file");
		return 1;
	}

	if (trace_start(trace)) {
		trace_perror(trace,"Starting trace");
		trace_destroy(trace);
		return 1;
	}

	packet = trace_create_packet();

	while (trace_read_packet(trace,packet)>0) {
		per_packet(packet);
	}

	trace_destroy_packet(packet);

	if (trace_is_err(trace)) {
		trace_perror(trace,"Reading packets");
		trace_destroy(trace);
		return 1;
	}

	trace_destroy(trace);

	return 0;
}
