/* Trivial parallel libtrace skeleton program
 *
 * This libtrace skeleton has the bare minimum required to write a useful
 * libtrace program, including error handling.
 *
 *
 */
/* Note we include libtrace_parallel.h rather then libtrace.h */
#include "libtrace_parallel.h"
#include <stdio.h>
#include <assert.h>

static void process_packet(libtrace_packet_t *packet)
{
	/* You really should consider using complete_parallel.c instead */
	assert(packet);

	/* Your code goes here */

}

/* Every time a packet becomes ready this function will be called. It will also
 * be called when messages from the library are received. This function
 * is run in parallel.
 */
static void* per_packet(libtrace_t *trace UNUSED, libtrace_thread_t *t UNUSED,
                        int mesg, libtrace_generic_t data,
                        libtrace_thread_t *sender UNUSED)
{

	switch (mesg) {
	case MESSAGE_PACKET:
		process_packet(data.pkt);
		/* If we have finished processing this packet return it */
		return data.pkt;
	default:
		return NULL;
	}
	return NULL;
}


int main(int argc, char *argv[])
{
	libtrace_t *trace;

	if (argc<2) {
		fprintf(stderr,"usage: %s libtraceuri\n",argv[0]);
		return 1;
	}

	trace = trace_create(argv[1]);

	if (trace_is_err(trace)) {
		trace_perror(trace,"Opening trace file");
		return 1;
	}

	/* We use a new version of trace_start(), trace_pstart()
	 * The reporter function argument is optional and can be NULL */
	if (trace_pstart(trace, NULL, per_packet, NULL)) {
		trace_perror(trace,"Starting trace");
		trace_destroy(trace);
		return 1;
	}

	/* Wait for the trace to finish */
	trace_join(trace);

	if (trace_is_err(trace)) {
		trace_perror(trace,"Reading packets");
		trace_destroy(trace);
		return 1;
	}

	trace_destroy(trace);

	return 0;
}
