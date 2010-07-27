/* Trivial libtrace program that counts the number of packets in a trace.
 * Designed to demonstrate the use of trace_read_packet()
 */
#include "libtrace.h"
#include <stdio.h>
#include <inttypes.h>
#include <err.h>
#include <assert.h>

uint64_t count = 0;


static void per_packet(libtrace_packet_t *packet)
{
	assert(packet);
	/* This function turns out to be really simple, because we are just
	 * counting the number of packets in the trace */
	count += 1;
}

/* Due to the amount of error checking required in our main function, it
 * is a lot simpler and tidier to place all the calls to various libtrace
 * destroy functions into a separate function.
 */
static void libtrace_cleanup(libtrace_t *trace, libtrace_packet_t *packet) {
	
	/* It's very important to ensure that we aren't trying to destroy
	 * a NULL structure, so each of the destroy calls will only occur
	 * if the structure exists */
	if (trace)
		trace_destroy(trace);
	
	if (packet)
		trace_destroy_packet(packet);

}


int main(int argc, char *argv[])
{
	libtrace_t *trace = NULL;
	libtrace_packet_t *packet = NULL;
	
	/* Creating and initialising a packet structure to store the packets
	 * that we're going to read from the trace */
	packet = trace_create_packet();

	/* Ensure we have at least one argument after the program name */
        if (argc < 2) {
                fprintf(stderr, "Usage: %s inputURI\n", argv[0]);
                return 1;
        }
	
	if (packet == NULL) {
		/* Unfortunately, trace_create_packet doesn't use the libtrace
		 * error system. This is because libtrace errors are associated
		 * with the trace structure, not the packet. In our case, we
		 * haven't even created a trace at this point so we can't 
		 * really expect libtrace to set an error on it for us, can
		 * we?
		 */
		perror("Creating libtrace packet");
		libtrace_cleanup(trace, packet);
		return 1;
	}

	/* Opening and starting the input trace, as per createdemo.c */
	trace = trace_create(argv[1]);

	if (trace_is_err(trace)) {
		trace_perror(trace,"Opening trace file");
		libtrace_cleanup(trace, packet);
		return 1;
	}

	if (trace_start(trace) == -1) {
		trace_perror(trace,"Starting trace");
		libtrace_cleanup(trace, packet);
		return 1;
	}

	/* This loop will read packets from the trace until either EOF is
	 * reached or an error occurs (hopefully the former!)
	 *
	 * Remember, EOF will return 0 so we only want to continue looping
	 * as long as the return value is greater than zero
	 */
	while (trace_read_packet(trace,packet)>0) {
		/* Call our per_packet function for every packet */
		per_packet(packet);
	}

	/* If the trace is in an error state, then we know that we fell out of
	 * the above loop because an error occurred rather than EOF being
	 * reached. Therefore, we should probably tell the user that something
	 * went wrong
	 */
	if (trace_is_err(trace)) {
		trace_perror(trace,"Reading packets");
		libtrace_cleanup(trace, packet);
		return 1;
	}

	/* We've reached the end of our trace without an error so we can
	 * print our final count. Note the use of the PRIu64 format which is
	 * portable across 64 and 32 bit machines */
	printf("Packet Count = %" PRIu64 "\n", count);
	
	libtrace_cleanup(trace, packet);

	return 0;
}
