/* Trivial libtrace program that writes all SMTP packets from a trace into 
 * a new separate trace.
 *
 * Designed to demonstrate the use of the libtrace output API
 */
#include "libtrace.h"
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>

static int per_packet(libtrace_out_t *output, libtrace_packet_t *packet)
{
	libtrace_tcp_t *tcp;

	/* Get the TCP header using trace_get_tcp() */
	tcp = trace_get_tcp(packet);
	
	/* If the packet does not have a TCP header, skip it */
	if (tcp == NULL)
		return 0;

	/* Check if either port in the TCP header is 25. Note that we
	 * have to byteswap the port numbers because we are reading directly
	 * out of the zero-copied packet */
	if ((ntohs(tcp->source) == 25) || (ntohs(tcp->dest) == 25)) {
		/* If we have a match, write the packet to our output trace,
		 * being sure to check for errors */
		if (trace_write_packet(output, packet) == -1) {
			trace_perror_output(output, "Writing packet");
			return -1;
		}
	}
	return 0;
}

/* The cleanup function has now been extended to destroy the output trace as
 * well */
static void libtrace_cleanup(libtrace_t *trace, libtrace_out_t *output, 
		libtrace_packet_t *packet) {

        /* It's very important to ensure that we aren't trying to destroy
         * a NULL structure, so each of the destroy calls will only occur
         * if the structure exists */
        if (trace)
                trace_destroy(trace);

	if (output)
		trace_destroy_output(output);

        if (packet)
                trace_destroy_packet(packet);

}

int main(int argc, char *argv[])
{
        /* Unlike most of the other example programs, this is not a copy and
	 * paste job from readdemo.c as we now also have to initalise and
	 * start an output trace too */

        libtrace_t *trace = NULL;
        libtrace_packet_t *packet = NULL;
	libtrace_out_t *output = NULL;

	/* Check that we have all the required command line arguments */
	if (argc < 3) {
		fprintf(stderr, "Usage: %s inputURI outputURI\n", argv[0]);
		return 1;
	}
	
	/* Creating the packet structure */
        packet = trace_create_packet();

        if (packet == NULL) {
                perror("Creating libtrace packet");
                libtrace_cleanup(trace, output, packet);
                return 1;
        }

	/* Creating and starting the INPUT trace */
        trace = trace_create(argv[1]);

        if (trace_is_err(trace)) {
                trace_perror(trace,"Opening trace file");
                libtrace_cleanup(trace, output, packet);
                return 1;
        }

        if (trace_start(trace) == -1) {
                trace_perror(trace,"Starting trace");
                libtrace_cleanup(trace, output, packet);
                return 1;
        }

	/* Creating and starting the OUTPUT trace */
        output = trace_create_output(argv[2]);

        if (trace_is_err_output(output)) {
                trace_perror_output(output,"Opening output trace file");
                libtrace_cleanup(trace, output, packet);
                return 1;
        }

        if (trace_start_output(output) == -1) {
                trace_perror_output(output,"Starting output trace");
                libtrace_cleanup(trace, output, packet);
                return 1;
        }
        
	while (trace_read_packet(trace,packet)>0) {
                
		/* If something goes wrong when writing packets, we need to
		 * catch that error, tidy up and exit */
		if (per_packet(output, packet) == -1) {
			libtrace_cleanup(trace, output, packet);
			return 1;
		}
        }

	/* Checking for any errors that might have occurred while reading the
	 * input trace */
        if (trace_is_err(trace)) {
                trace_perror(trace,"Reading packets");
                libtrace_cleanup(trace, output, packet);
                return 1;
        }

        libtrace_cleanup(trace, output, packet);
        return 0;
}

