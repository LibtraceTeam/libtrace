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


int main(int argc UNUSED, char *argv[] UNUSED) {

	libtrace_t *trace = NULL;
        libtrace_packet_t *packet = NULL;
	uint32_t mplslabel;
	uint8_t *mplsptr;
	uint32_t remaining;
	int error = 0;

	packet = trace_create_packet();

	trace = trace_create("pcapfile:traces/mpls.pcap");
	iferr(trace);

	trace_start(trace);
	iferr(trace);

	/* read a packet */
	trace_read_packet(trace, packet);

	mplslabel = trace_get_outermost_mpls(packet, &mplsptr, &remaining);
	if (mplslabel != 18) {
		printf("Failed to find correct outermost MPLS tag\n");
		error = 1;
	}

	/* Second packet should not contain a MPLS label */
	trace_read_packet(trace, packet);
	mplslabel = trace_get_outermost_mpls(packet, &mplsptr, &remaining);
	if (mplslabel != MPLS_NOT_FOUND) {
		printf("Found MPLS label with none present\n");
		error = 1;
	}

	/* read a packet */
	trace_read_packet(trace, packet);
	mplslabel = trace_get_outermost_mpls(packet, &mplsptr, &remaining);
	if (mplslabel != 18) {
		printf("Failed to find correct outermost MPLS tag\n");
                error = 1;
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
