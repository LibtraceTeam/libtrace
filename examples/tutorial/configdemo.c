 /* Another implementation of tracefilter that demonstrates the use of the
  * configuration system for traces
 */
#include "libtrace.h"
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>

static int per_packet(libtrace_out_t *output, libtrace_packet_t *packet)
{
	/* All packets that reach this function must have matched the filter
	 * so we can write them out immediately */
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

	int level = 6;
	trace_option_compresstype_t method = TRACE_OPTION_COMPRESSTYPE_ZLIB;

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

	/* Creating the filter */
	filter = trace_create_filter(argv[2]);
	if (filter == NULL) {
		fprintf(stderr, "Failed to create filter (%s)\n", argv[2]);
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

	/* Use the configuration system to tell libtrace to always use this
	 * filter when reading packets. For live captures, this means the
	 * filter will be pushed into the kernel or hardware, improving
	 * the performance over a software filter.
	 *
	 * Note that the configuration is performed BEFORE calling 
	 * trace_start(). 
	 */

	if (trace_config(trace, TRACE_OPTION_FILTER, filter) == -1) {
		trace_perror(trace, "Configuring filter");
		libtrace_cleanup(trace, output, packet, filter);
		return 1;
	}

        if (trace_start(trace) == -1) {
                trace_perror(trace,"Starting trace");
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

	/* We want to write compressed output, so tell libtrace which 
	 * compression format to use for our output trace. 
	 * 
	 * Not configuring this will result in uncompressed output, 
	 * regardless of whether a compression level is set or not. This
	 * is different behaviour to earlier versions of libtrace where
	 * the default was to produce a compressed file.
	 */
	if (trace_config_output(output, TRACE_OPTION_OUTPUT_COMPRESSTYPE, 
			&method) == -1) {
		trace_perror_output(output, "Configuring compression method");
		libtrace_cleanup(trace, output, packet, filter);
		return 1;
	}

        /* We're also going to set a compression level option for the output
	 * trace to ensure that our traces are compressed sensibly.
	 *
	 * Again, this must be done before calling trace_start_output().
	 */
	
	if (trace_config_output(output, TRACE_OPTION_OUTPUT_COMPRESS, &level) == -1) {
		trace_perror_output(output, "Configuring compression level");
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
		if (per_packet(output, packet) == -1) {
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

