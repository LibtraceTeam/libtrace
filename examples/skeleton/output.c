/* An example program that demonstrates libtrace's output functionalities.
 *
 * This libtrace skeleton has the bare minimum required to write a useful
 * libtrace output program, including error handling.
 *
 */
#include "libtrace.h"
#include <stdio.h>
#include <assert.h>

static void per_packet(libtrace_packet_t *packet)
{
	assert(packet);
	/* Your code goes here */
}

int main(int argc, char *argv[])
{
	libtrace_t *trace;
	libtrace_out_t *output;
	libtrace_packet_t *packet;
	int compress_level = 6;
	
	if (argc<3) {
		fprintf(stderr,"usage: %s <input uri> <outputuri>\n",argv[0]);
		return 1;
	}

	trace = trace_create(argv[1]);

	if (trace_is_err(trace)) {
		trace_perror(trace,"Opening input trace");
		return 1;
	}

	if (trace_start(trace)) {
		trace_perror(trace,"Starting input trace");
		trace_destroy(trace);
		return 1;
	}

	/* Creating output trace */
	output = trace_create_output(argv[2]);
	
	if (trace_is_err_output(output)) {
		trace_perror_output(output, "Opening output trace");
		return 1;
	}

	/* Setting compression level */
	if (trace_config_output(output, TRACE_OPTION_OUTPUT_COMPRESS, 
				&compress_level) == -1) {
		trace_perror_output(output, "Setting compression level");
		trace_destroy(trace);
		trace_destroy_output(output);
		return 1;
	}
	
	if (trace_start_output(output)) {
		trace_perror_output(output, "Starting output trace");
		trace_destroy_output(output);
		trace_destroy(trace);
		return 1;
	}
		
	packet = trace_create_packet();

	while (trace_read_packet(trace,packet)>0) {
		/* Perhaps we want to do something to the packet first */
		per_packet(packet);

		/* Write out the packet */
		if (trace_write_packet(output, packet) < 0) {
			trace_perror_output(output, "Writing packet");
			trace_destroy(trace);
			trace_destroy_output(output);
			trace_destroy_packet(packet);
			return 1;
		}
		
	}
	

	if (trace_is_err(trace)) {
		trace_perror(trace,"Reading packets");
		trace_destroy(trace);
		trace_destroy_output(output);
		trace_destroy_packet(packet);
		return 1;
	}

	trace_destroy(trace);
	trace_destroy_output(output);
	trace_destroy_packet(packet);
	
	return 0;
}
