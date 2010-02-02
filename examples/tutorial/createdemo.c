/* Skeleton libtrace program that demonstrates how to create, start and 
 * destroy a trace in a nice clean manner with full error-checking (because
 * error handling is good!)
 */

/* All libtrace programs require libtrace.h to be included */
#include "libtrace.h"
#include <stdio.h>

int main(int argc, char *argv[])
{
	libtrace_t *trace;
	
        /* Ensure we have at least one argument after the program name */
        if (argc < 2) {
                fprintf(stderr, "Usage: %s inputURI\n", argv[0]);
		return 1;
        }
	
	/* trace_create initialises our trace structure */
	trace = trace_create(argv[1]);

	/* Check if an error occurred, i.e. the URI was incorrect or the file
	 * does not exist */
	if (trace_is_err(trace)) {
		trace_perror(trace,"Opening trace file");
		return 1;
	}

	/* Start the trace, being sure to check if any error occurs during the
	 * starting phase */
	if (trace_start(trace) == -1) {
		trace_perror(trace,"Starting trace");
		trace_destroy(trace);
		return 1;
	}

	/* Now our trace is open and ready for reading, but that is beyond
	 * the scope of this example */

	/* Program is over, so destroy the trace structure */
	trace_destroy(trace);
	return 0;
}
