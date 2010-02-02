 /* Simple implementation of tracefilter that demonstrates the use of the
  * filter creation and application functions
 */
#include "libtrace.h"
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>

static int per_packet(libtrace_out_t *output, libtrace_packet_t *packet, 
		libtrace_filter_t *filter)
{
	int ret;

	/* Apply the filter to the packet */
	ret = trace_apply_filter(filter, packet);

	/* Check for any errors that occur during the filtering process */
	if (ret == -1) {
		fprintf(stderr, "Error applying filter\n");
		return -1;
	}

	/* If we get a return value of zero, the packet did not match the
	 * filter so we want to return immediately
	 */
	if (ret == 0)
		return 0;

	/* Otherwise, the packet matched our filter so we should write it to
	 * our output trace */
	if (trace_write_packet(output, packet) == -1) {
		trace_perror_output(output, "Writing packet");
		return -1;
	}

	return 0;
}

/* The cleanup function has now been extended to destroy the filter and 
 * output trace as well */
static void libtrace_cleanup(libtrace_t *trace, libtrace_out_t *output, 
		libtrace_packet_t *packet, libtrace_filter_t *filter) {

        /* It's very important to ensure that we aren't trying to destroy
         * a NULL structure, so each of the destroy calls will only occur
         * if the structure exists */
        if (trace)
                trace_destroy(trace);

	if (output)
		trace_destroy_output(output);

        if (packet)
                trace_destroy_packet(packet);

	if (filter)
		trace_destroy_filter(filter);

}

int main(int argc, char *argv[])
{
        /* Unlike most of the other example programs, this is not a copy and
	 * paste job from readdemo.c as we now also have to initalise and
	 * start an output trace too */

	/* On top of that, we now have to manage a filter as well */

        libtrace_t *trace = NULL;
        libtrace_packet_t *packet = NULL;
	libtrace_out_t *output = NULL;
	libtrace_filter_t *filter = NULL;

	/* Check that we have all the required command line arguments */
	if (argc < 4) {
		fprintf(stderr, "Usage: %s inputURI bpffilter outputURI\n", 
			argv[0]);
		return 1;
	}
	
	/* Creating the packet structure */
        packet = trace_create_packet();

        if (packet == NULL) {
                perror("Creating libtrace packet");
                libtrace_cleanup(trace, output, packet, filter);
                return 1;
        }

	/* Creating and starting the INPUT trace */
        trace = trace_create(argv[1]);

        if (trace_is_err(trace)) {
                trace_perror(trace,"Opening trace file");
                libtrace_cleanup(trace, output, packet, filter);
                return 1;
        }

        if (trace_start(trace) == -1) {
                trace_perror(trace,"Starting trace");
                libtrace_cleanup(trace, output, packet, filter);
                return 1;
        }

	/* Creating the filter */
	filter = trace_create_filter(argv[2]);
	if (filter == NULL) {
		fprintf(stderr, "Failed to create filter (%s)\n", argv[2]);
		libtrace_cleanup(trace, output, packet, filter);
		return 1;
	}
	
	/* Creating and starting the OUTPUT trace */
        output = trace_create_output(argv[3]);

        if (trace_is_err_output(output)) {
                trace_perror_output(output,"Opening output trace file");
                libtrace_cleanup(trace, output, packet, filter);
                return 1;
        }

        if (trace_start_output(output) == -1) {
                trace_perror_output(output,"Starting output trace");
                libtrace_cleanup(trace, output, packet, filter);
                return 1;
        }
        
	while (trace_read_packet(trace,packet)>0) {
                
		/* If something goes wrong when writing packets, we need to
		 * catch that error, tidy up and exit */
		if (per_packet(output, packet, filter) == -1) {
			libtrace_cleanup(trace, output, packet, filter);
			return 1;
		}
        }

	/* Checking for any errors that might have occurred while reading the
	 * input trace */
        if (trace_is_err(trace)) {
                trace_perror(trace,"Reading packets");
                libtrace_cleanup(trace, output, packet, filter);
                return 1;
        }

        libtrace_cleanup(trace, output, packet, filter);
        return 0;
}

