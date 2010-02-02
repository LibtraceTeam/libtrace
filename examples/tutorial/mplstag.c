/* Trivial libtrace program that prints all the MPLS tags within a packet.
 * Designed to demonstrate the use of trace_get_payload_from_mpls()
 */
#include "libtrace.h"
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>

static void print_mpls_label(void *mpls, uint32_t remaining) {
	uint32_t label = 0;
	if (remaining < 4)
		return;

	/* Cast MPLS header into a 32 bit number */
	label = *(uint32_t *)mpls;
	/* Label number is in network byte order */
	label = ntohl(label);
	/* MPLS labels are comprise only 20 of the 32 bits in the header */
	label = (label >> 12) & 0x000fffff;

	printf("%u ", label);
}


static void per_packet(libtrace_packet_t *packet)
{
	void *l2 = NULL;
	void *l2_payload = NULL;
	libtrace_linktype_t link_type;
	uint16_t ethertype;
	uint32_t remaining;

	l2 = trace_get_layer2(packet, &link_type, &remaining);
	
	/* No layer 2 header */
	if (l2 == NULL)
		return;

	
	/* XXX We could check if link_type is ethernet here, but this won't
	 * affect our results in any way */
	l2_payload = trace_get_payload_from_layer2(l2, link_type, &ethertype,
		&remaining);
	
	/* Incomplete layer 2 header */
	if (l2_payload == NULL)
		return;
	
	/* No actual payload after the layer 2 header */
	if (remaining == 0)
		return;

	/* Only look for MPLS labels as long as we have payload available
	 * to look at! */
	while (l2_payload != NULL && remaining > 0) {
		
		/* 0x8847 is the ethertype for MPLS headers */
		if (ethertype == 0x8847) {
			print_mpls_label(l2_payload, remaining);
			/* Move onto the next header */
			l2_payload = trace_get_payload_from_mpls(l2_payload,
					&ethertype, &remaining);
		} else 
			/* Stop as soon as we encounter a non-MPLS header */
			break;
	}
	
	printf("\n");

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


        libtrace_cleanup(trace, packet);
        return 0;
}

