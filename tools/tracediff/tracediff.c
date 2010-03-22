/* Tool that compares two traces and outputs any packets that do not match
 * between the two
 *
 * Author: Shane Alcock
 */

#include "libtrace.h"
#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>

#include "libpacketdump.h"

uint32_t max_diff = 0;
uint32_t dumped_diff = 0;

/* Compares the two provided packets. If the packets differ in any fashion,
 * both will be dumped to standard output using libpacketdump followed by a
 * line of asterisks.
 *
 * Note that only the contents of the packet are compared; the framing provided
 * by the trace format, e.g. the ERF or PCAP header, is not examined.
 */
static void per_packet(libtrace_packet_t *a, libtrace_packet_t *b)
{
	char *buf_a, *buf_b;
	libtrace_linktype_t lt;
	uint32_t rem_a, rem_b;


	buf_a = trace_get_packet_buffer(a, &lt, &rem_a);
	buf_b = trace_get_packet_buffer(b, &lt, &rem_b);

	if (rem_a > trace_get_wire_length(a))
		rem_a = trace_get_wire_length(a);
	if (rem_b > trace_get_wire_length(b))
		rem_b = trace_get_wire_length(b);
	

	if (!buf_a && !buf_b)
		return;

	if (!buf_a || !buf_b) {
		trace_dump_packet(a);
		trace_dump_packet(b);
		printf("****************\n");
		dumped_diff ++;
		return;
	}
		

	if (rem_a == 0 || rem_b == 0)
		return;

	if (rem_a != rem_b) {
		trace_dump_packet(a);
		trace_dump_packet(b);
		printf("****************\n");
		dumped_diff ++;
		return;
	}

	/* This is not exactly going to be snappy, but it's the easiest way
	 * to look for differences */
	if (memcmp(buf_a, buf_b, rem_a) != 0) {
		trace_dump_packet(a);
		trace_dump_packet(b);
		printf("****************\n");
		dumped_diff ++;
	}

}

static void usage(char *prog) {
	printf("Usage instructions for %s\n\n", prog);
	printf("\t%s [options] traceA traceB\n\n", prog);
	printf("Supported options:\n");
	printf("\t-m <max>   Stop after <max> differences have been reported\n");

	
	return;

}

int main(int argc, char *argv[])
{
	libtrace_t *trace[2];
	libtrace_packet_t *packet[2];
	int opt;
	
	if (argc<2) {
		usage(argv[0]);
		return -1;
	}

	while ((opt = getopt(argc, argv, "m:")) != EOF) {
		switch (opt) {
			case 'm':
				if (atoi(optarg) < 0) {
					fprintf(stderr, "-m option must not be negative - ignoring\n");
				} else {
					max_diff = (uint32_t) atoi(optarg);
				}
				break;
			default:
				usage(argv[0]);
		}
	}

	if (optind + 2 > argc) {
		usage(argv[0]);
		return -1;
	}
	packet[0] = trace_create_packet();
	packet[1] = trace_create_packet();

	trace[0] = trace_create(argv[optind++]);

	if (trace_is_err(trace[0])) {
		trace_perror(trace[0],"Opening trace file");
		return -1;
	}

	if (trace_start(trace[0])) {
		trace_perror(trace[0],"Starting trace");
		trace_destroy(trace[0]);
		return -1;
	}

	trace[1] = trace_create(argv[optind++]);

	if (trace_is_err(trace[1])) {
		trace_perror(trace[1],"Opening trace file");
		return -1;
	}

	if (trace_start(trace[1])) {
		trace_perror(trace[1],"Starting trace");
		trace_destroy(trace[1]);
		return -1;
	}

	while (trace_read_packet(trace[0], packet[0]) > 0 &&
			trace_read_packet(trace[1], packet[1]) > 0) {

		per_packet(packet[0], packet[1]);

		if (max_diff > 0 && dumped_diff >= max_diff)
			break;

	}

	if (trace_is_err(trace[0])) {
		trace_perror(trace[0],"Reading packets");
		trace_destroy(trace[0]);
		return -1;
	}
	
	if (trace_is_err(trace[1])) {
		trace_perror(trace[1],"Reading packets");
		trace_destroy(trace[1]);
		return -1;
	}

	trace_destroy(trace[0]);
	trace_destroy(trace[1]);
		
	trace_destroy_packet(packet[0]);
	trace_destroy_packet(packet[1]);
	
	if (dumped_diff == 0)
		return 0;
	else
		return 1;
}
