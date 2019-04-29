/* Obtains a libtrace_layer2_headers structure for a packet containing all known layer2 headers */

#include "libtrace.h"
#include <stdio.h>

int packet_count = 0;

static void per_packet(libtrace_packet_t *packet) {
	libtrace_layer2_headers_t *headers;

	int i;
	uint32_t vlanhdr;
	uint16_t vlanid;
	uint32_t mplshdr;
	uint32_t mplslabel;

	/* get the layer2 headers for the packet */
	headers = trace_get_layer2_headers(packet);

	if (headers != NULL) {

		printf("Packet %d layer2 headers:\n", packet_count);

		for (i=0;i<headers->num;i++) {

			/* check if this header is a vlan header */
			if (headers->header[i].ethertype == TRACE_ETHERTYPE_8021Q) {
				/* get the vlanid from the data pointer */
				vlanhdr = ntohl(*(uint32_t *) headers->header[i].data);
                        	vlanid = (((vlanhdr >> 16) << 4) >> 4);
				fprintf(stderr, "\tvlan id of %u\n", vlanid);
			}

			/* check if this header is a vlan header */
                        if (headers->header[i].ethertype == TRACE_ETHERTYPE_8021QS) {
				/* get the vlanid from the data pointer */
                                vlanhdr = ntohl(*(uint32_t *) headers->header[i].data);
                                vlanid = (((vlanhdr >> 16) << 4) >> 4);
                                fprintf(stderr, "\tservice vlan id of %u\n", vlanid);
                        }

			/* check if this header is a mpls header */
                        if (headers->header[i].ethertype == TRACE_ETHERTYPE_MPLS) {
                                mplshdr = ntohl(*(uint32_t *)headers->header[i].data);
        			mplslabel = mplshdr >> 12;
                                fprintf(stderr, "\tmpls label of %u\n", mplslabel);
                        }

			/* check if this header is a PPP discovery header */
                        if (headers->header[i].ethertype == TRACE_ETHERTYPE_PPP_DISC) {
                                fprintf(stderr, "\tPPP discovery header\n");
                        }

			/* check if this header is a PPP session header */
                        if (headers->header[i].ethertype == TRACE_ETHERTYPE_PPP_SES) {
                                fprintf(stderr, "\tPPP session header\n");
                        }

			/* check if this header is a ARP header */
                        if (headers->header[i].ethertype == TRACE_ETHERTYPE_ARP) {
                                fprintf(stderr, "\tARP header\n");
                        }
		}

		/* Destroy the layer2 headers structure */
		trace_destroy_layer2_headers(headers);
	} else {
		printf("Packet %d does not contain any known layer2 headers\n", packet_count);
	}

	packet_count++;
}

static void libtrace_cleanup(libtrace_t *trace, libtrace_packet_t *packet) {
	if (trace) {
		trace_destroy(trace);
	}
	if (packet) {
		trace_destroy_packet(packet);
	}
}

int main(int argc, char *argv[]) {

	libtrace_t *trace = NULL;
	libtrace_packet_t *packet = NULL;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s inputURI\n", argv[0]);
		return 1;
	}

	/* create the trace */
	trace = trace_create(argv[1]);
	if (trace_is_err(trace)) {
		trace_perror(trace, "Opening trace file");
		libtrace_cleanup(trace, packet);
		return 1;
	}

	/* create the packet */
	packet = trace_create_packet();
	if (packet == NULL) {
		perror("Creating libtrace packet");
		libtrace_cleanup(trace, packet);
		return 1;
	}

	/* start the trace */
	if (trace_start(trace) == -1) {
		trace_perror(trace, "Starting trace");
		libtrace_cleanup(trace, packet);
		return 1;
	}

	/* read the packets */
	while (trace_read_packet(trace, packet) > 0) {
		per_packet(packet);
	}

	/* ensure trace is not in an error state */
	if (trace_is_err(trace)) {
		trace_perror(trace, "Reading packets");
		libtrace_cleanup(trace, packet);
		return 1;
	}

	libtrace_cleanup(trace, packet);
	return 0;
}
