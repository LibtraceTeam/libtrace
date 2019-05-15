#include "libtrace.h"
#include <stdio.h>
#include <stdlib.h>

void iferr(libtrace_t *trace)
{
        libtrace_err_t err = trace_get_err(trace);
        if (err.err_num==0)
                return;
        printf("Error: %s\n",err.problem);
        exit(1);
}


int main(int argc, char *argv[]) {

	libtrace_t *trace = NULL;
        libtrace_packet_t *packet = NULL;
	int i = 0;
	uint16_t mplslabel;
	uint8_t *mplsptr;
	uint32_t remaining;
	int error = 0;

	packet = trace_create_packet();

	trace = trace_create("pcapfile:traces/mpls.pcap");
	iferr(trace);

	trace_start(trace);
	iferr(trace);

	/* read a packet, get its layer2 headers and test they are correct */
	trace_read_packet(trace, packet);
	libtrace_layer2_headers_t *hdr = trace_get_layer2_headers(packet);
	if (hdr != NULL) {
		trace_destroy_layer2_headers(hdr);
	}

	trace_read_packet(trace, packet);
        hdr = trace_get_layer2_headers(packet);
	if (hdr != NULL) {
        	printf("Found unexpected layer2 header\n");
		trace_destroy_layer2_headers(hdr);
		error = 1;
	}

	trace_read_packet(trace, packet);
        hdr = trace_get_layer2_headers(packet);
	if (hdr == NULL) {
		printf("Was expecting to find MPLS header\n");
		error = 1;
	} else {
		if (hdr->num != 1) {
			printf("Found unexpected number of layer2 headers\n");
			error = 1;
		} else {
			if ((hdr->bitmask & TRACE_BITMASK_MPLS) != TRACE_BITMASK_MPLS) {
				printf("Found unexpected bitmask for layer2 headers\n");
				error = 1;
			}
		}
		trace_destroy_layer2_headers(hdr);
	}

	if (error == 0) {
		printf("success\n");
	} else {
		iferr(trace);
	}

	trace_destroy(trace);
	trace_destroy_packet(packet);

	return error;
}
