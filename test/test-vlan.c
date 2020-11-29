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
	uint16_t vlanid;
	uint8_t *vlanptr;
	uint32_t remaining;
	int error = 0;

	packet = trace_create_packet();

	trace = trace_create("pcapfile:traces/vlan.pcap");
	iferr(trace);

	trace_start(trace);
	iferr(trace);

	/* read a packet */
	trace_read_packet(trace, packet);
	/* first packet in this trace should have a vlan tag of 32 */
	vlanid = trace_get_outermost_vlan(packet, &vlanptr, &remaining);
	if (vlanid != 32) {
		printf("Failed to find correct outermost vlan tag\n");
		error = 1;
	}

	/* read a packet */
	trace_read_packet(trace, packet);
	vlanid = trace_get_outermost_vlan(packet, &vlanptr, &remaining);
	if (vlanid != 32) {
		printf("Failed to find correct outermost vlan tag\n");
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
