/* Trivial libtrace program that counts the number of HTTP packets in a trace.
 * Designed to demonstrate the use of trace_get_transport()
 */
#include "libtrace.h"
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>

uint64_t count = 0;


static void per_packet(libtrace_packet_t *packet)
{
	void *transport;
	uint8_t proto;
	uint32_t remaining;
	libtrace_tcp_t *tcp;

	/* Remember that both proto and remaining will be set for us by
	 * this function, so we need to pass in pointers to pre-existing
	 * variables. Any values in those variables will be ignored and 
	 * replaced by trace_get_transport
	 */	
	transport = trace_get_transport(packet, &proto, &remaining);

	/* If the packet does not have a transport header, skip it */
	if (transport == NULL)
		return;
	
	/* If the transport header is not TCP, skip it */
	if (proto != 6)
		return;

	/* Cast the transport header into a TCP header */
	tcp = (libtrace_tcp_t *)transport;

	/* Check if either port in the TCP header is 80. Note that we have
	 * to byteswap the port numbers because we are reading directly out
	 * of the zero-copied packet */
	if ((ntohs(tcp->source) == 80) || (ntohs(tcp->dest) == 80))
		count += 1;
}

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

	printf("Packet Count = %" PRIu64 "\n", count);

        libtrace_cleanup(trace, packet);
        return 0;
}

