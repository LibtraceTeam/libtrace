/* Trivial libtrace program that counts the number of MPLS packets in a trace.
 * Designed to demonstrate the use of trace_get_payload_from_layer2()
 */
#include "libtrace.h"
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>

uint64_t count = 0;


static void per_packet(libtrace_packet_t *packet)
{
	void *l2 = NULL;
	void *l2_payload = NULL;
	libtrace_linktype_t link_type;
	uint16_t ethertype;
	uint32_t remaining;

	/* Jump straight to the link layer header */
	l2 = trace_get_layer2(packet, &link_type, &remaining);
	
	/* No layer 2 header */
	if (l2 == NULL)
		return;
	
	/* XXX We could check if link_type is ethernet here, but this won't
	 * affect our results in any way */


	/* Skip past the initial layer 2 header to look for an MPLS header */
	l2_payload = trace_get_payload_from_layer2(l2, link_type, &ethertype,
		&remaining);
	
	/* Incomplete layer 2 header */
	if (l2_payload == NULL)
		return;

	/* Zero bytes of payload remaining so there is no useful header
	 * available */
	if (remaining == 0)
		return;
	
	/* If the returned header is not an MPLS header, we want to return
	 * without incrementing our counter */
	if (ethertype != 0x8847)	
		return;

	/* Otherwise, we must have an MPLS tag - increment the counter */
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


