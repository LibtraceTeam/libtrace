/* Trivial libtrace program that prints the fields in the header for all
 * UDP packets in a trace.
 *
 * Designed to demonstrate the use of trace_get_transport()
 */
#include "libtrace.h"
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>
#include <arpa/inet.h>

static void per_packet(libtrace_packet_t *packet)
{
	uint8_t proto;
	uint32_t rem;
	void *transport = NULL;
	libtrace_udp_t *udp = NULL;

	/* OK, this is slightly tricky so pay attention.
	 * 
	 * proto and rem are used as 'output' parameters here. What this
	 * means is that their current values are ignored by the function
	 * but they are updated to contain the protocol and amount of 
	 * payload remaining for the header that is being returned.
	 * 
	 * We need to pass in the address of both these parameters, so
	 * that they can be modified by the function. This is why there
	 * is an '&' before both parameters.
	 */
	transport = trace_get_transport(packet, &proto, &rem);

	/* If there was no transport header, it can't be a UDP packet */
	if (transport == NULL)
		return;

	/* Check if the protocol is UDP, using the defined value for UDP 
	 * that is defined in libtrace.h (search for libtrace_ipproto_t for
	 * a full list) */
	if (proto != TRACE_IPPROTO_UDP)
		return;

	/* One last check - make sure we have a full UDP header before 
	 * trying to grab fields out of it */
	if (rem < sizeof(libtrace_udp_t))
		return;

	/* Now, cast the returned header to the appropriate header type */
	udp = (libtrace_udp_t *)transport;

	/* Dump each field to standard output. Be careful to byteswap any
	 * fields that are larger than one byte, as these will be in network
	 * byte order */
	printf("UDP: source=%u dest=%u len=%u checksum=%u\n",
			ntohs(udp->source), ntohs(udp->dest),
			ntohs(udp->len), ntohs(udp->check));
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
	/* This is essentially the same main function from readdemo.c */
	
	libtrace_t *trace = NULL;
	libtrace_packet_t *packet = NULL;

	/* Ensure we have at least one argument after the program name */
        if (argc < 2) {
                fprintf(stderr, "Usage: %s inputURI\n", argv[0]);
                return 1;
        }	
	
	packet = trace_create_packet();

	if (packet == NULL) {
		perror("Creating libtrace packet");
		libtrace_cleanup(trace, packet);
		return 1;
	}

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


	while (trace_read_packet(trace,packet)>0) {
		per_packet(packet);
	}


	if (trace_is_err(trace)) {
		trace_perror(trace,"Reading packets");
		libtrace_cleanup(trace, packet);
		return 1;
	}

	libtrace_cleanup(trace, packet);
	return 0;
}
