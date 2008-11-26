#include "libtrace.h"
#include <stdio.h>
#include <inttypes.h>
#include "lt_inttypes.h"

static uint64_t ignored = 0;

static struct libtrace_out_t *create_output(char *uri) {
	struct libtrace_out_t *output = NULL;
	output = trace_create_output(uri);
	if (trace_is_err_output(output)) {
		trace_perror_output(output,"%s",uri);
		trace_destroy_output(output);
		return NULL;
	}
	/* Default values for now */
	trace_start_output(output);
	if (trace_is_err_output(output)) {
		trace_perror_output(output,"%s",uri);
		trace_destroy_output(output);
		return NULL;
	}
	return output;
}

static void usage(char*argv0) {
	printf("%s inputuri outputuri_incoming outputuri_outgoing\n",argv0);
}

int main(int argc, char *argv[]) {
	struct libtrace_t *input = NULL;
	struct libtrace_out_t *in_write = NULL;
	struct libtrace_out_t *out_write = NULL;
	libtrace_err_t trace_err;
	struct libtrace_packet_t *packet = trace_create_packet();
	
	if (argc < 3) {
		usage(argv[0]);
		return 1;
	}

	input = trace_create(argv[1]);
	if (trace_is_err(input)) {
		trace_err = trace_get_err(input);
		printf("Problem reading input trace: %s\n", trace_err.problem);
		return 1;
	}
	if (trace_start(input)==-1) {
		trace_perror(input,"Unable to start trace: %s",argv[1]);
		return 1;
	}
	
	while(1) {
		if (trace_read_packet(input, packet) < 1)
			break;

		switch(trace_get_direction(packet)) {
			case TRACE_DIR_INCOMING:
				if (!out_write) {
					out_write = create_output(argv[3]);
					if (!out_write)
						return 1;
				}
				if (trace_write_packet(out_write, packet)==-1){
					trace_perror_output(in_write,"write");
					return 1;
				}
				break;
			case TRACE_DIR_OUTGOING:
				if (!in_write) {
					in_write = create_output(argv[2]);
					if (!in_write)
						return 1;
				}
				if (trace_write_packet(in_write, packet)==-1) {
					trace_perror_output(in_write,"write");
					return 1;
				}
				break;
			default:
				ignored++;
		}

	}
	if (out_write)
		trace_destroy_output(out_write);
	if (in_write)
		trace_destroy_output(in_write);
	trace_destroy(input);
	trace_destroy_packet(packet);

	if (ignored)
		fprintf(stderr,"warning: Ignored %" PRIu64 " packets with unknown directions\n",
				ignored);
	
	return 0;
}
	
