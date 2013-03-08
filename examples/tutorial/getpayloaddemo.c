/* Trivial libtrace program that prints the fields in the header for all
 * UDP packets in a trace. Instead of using trace_get_transport, we're going
 * to jump to the IP layer and use trace_get_payload_from_ip to find the UDP
 * header.
 *
 * Designed to demonstrate the use of trace_get_payload_from_X functions
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
	uint16_t ethertype;
	uint32_t rem;
	void *ltheader = NULL;
	libtrace_udp_t *udp = NULL;
	libtrace_ip_t *ip = NULL;
	libtrace_ip6_t *ip6 = NULL;

	/* OK, this is slightly tricky so pay attention.
	 * 
	 * ethertype and rem are used as 'output' parameters here. What this
	 * means is that their current values are ignored by the function
	 * but they are updated to contain the protocol and amount of 
	 * payload remaining for the header that is being returned.
	 * 
	 * We need to pass in the address of both these parameters, so
	 * that they can be modified by the function. This is why there
	 * is an '&' before both parameters.
	 */
	ltheader = trace_get_layer3(packet, &ethertype, &rem);

	/* If there was no layer 3 header, ignore the packet */
	if (ltheader == NULL)
		return;

	/* If there is no packet remaining, there is no point in going any
	 * further */
	if (rem == 0)
		return;

	/* Ok, we've got a layer 3 header - let's cast it to the appropriate
	 * type and use the appropriate get_payload function to find the next
	 * header. 
	 *
	 */
	if (ethertype == TRACE_ETHERTYPE_IP) {
		/* Our layer 3 header is IPv4 */
		
		/* Cast the returned header to a libtrace_ip_t */
		ip = (libtrace_ip_t *)ltheader;

		/* Use the get_payload_from_ip function to skip past the IPv4
		 * header. The key thing here is that rem needs to contain
		 * the same value that resulted from the earlier call to
		 * trace_get_layer3 */

		ltheader = trace_get_payload_from_ip(ip, &proto, &rem);

	} else if (ethertype == TRACE_ETHERTYPE_IPV6) {
		/* Our layer 3 header is IPv6 */
		
		/* Cast the returned header to a libtrace_ip6_t */
		ip6 = (libtrace_ip6_t *)ltheader;

		/* Use the get_payload_from_ip6 function to skip past the IPv6
		 * header. The key thing here is that rem needs to contain
		 * the same value that resulted from the earlier call to
		 * trace_get_layer3 */

		ltheader = trace_get_payload_from_ip6(ip6, &proto, &rem);

	} else {
		/* Let's ignore any other Layer 3 headers for now */
		return;
	}

	/* Check if there was a header present after the layer 3 header. */
	if (ltheader == NULL)
		return;

	/* Check if the protocol is UDP, using the defined value for UDP 
	 * that is defined in libtrace.h (search for libtrace_ipproto_t for
	 * a full list) */
	if (proto != TRACE_IPPROTO_UDP)
		return;

	/* One last check - make sure we have a full UDP header before 
	 * trying to grab fields out of it. */
	if (rem < sizeof(libtrace_udp_t))
		return;

	/* Now, cast the returned header to the appropriate header type */
	udp = (libtrace_udp_t *)ltheader;

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
