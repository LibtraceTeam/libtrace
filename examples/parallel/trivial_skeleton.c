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


/* Every time a packet becomes ready this function will be called. This
 * function is run in parallel, so multiple packets can be processed at once.
 *
 * Parameters:
 *   trace -- the input source that the packet was read from
 *   t -- a pointer to the current processing thread
 *   global -- a pointer to the global variable passed in to trace_start
 *   tls -- a pointer to the thread local storage for this thread
 *   packet -- the packet itself
 */
static libtrace_packet_t *process_packet(libtrace_t *trace,
                libtrace_thread_t *t,
                void *global, void *tls, libtrace_packet_t *packet) {

        /* Note that in this example, global and tls will both be NULL.
         * global is NULL because we passed NULL as the second argument
         * for trace_pstart. tls is NULL because we did not set a
         * starting callback for our per packet threads.
         */


        assert(packet);

        /* Your code goes here */

        /* If we've finished with the packet, we should return it to
         * libtrace so that it can be reused. */
        return packet;
}

int main(int argc, char *argv[])
{
	libtrace_t *trace;
        libtrace_callback_set_t *pktcbs;

	if (argc<2) {
		fprintf(stderr,"usage: %s libtraceuri\n",argv[0]);
		return 1;
	}

	trace = trace_create(argv[1]);

	if (trace_is_err(trace)) {
		trace_perror(trace,"Opening trace file");
		return 1;
	}

        /* Create a callback set for our per packet threads */
        pktcbs = trace_create_callback_set();

        /* Set the packet callback to be our packet processing function */
        trace_set_packet_cb(pktcbs, process_packet);

	/* We use a new version of trace_start(), trace_pstart()
	 * The reporter function argument is optional and can be NULL.
         * We've also set the second argument to NULL because we have no
         * global data that we want to be available to all threads. */
	if (trace_pstart(trace, NULL, pktcbs, NULL)) {
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
        trace_destroy_callback_set(pktcbs);

	return 0;
}
