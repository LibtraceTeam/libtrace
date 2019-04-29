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
	libtrace_layer2_headers_t *headers;
	int error = 0;
	uint32_t vlanhdr;
	uint16_t vlanid;

	packet = trace_create_packet();

	trace = trace_create("pcapfile:traces/qinq.pcap");
	iferr(trace);

	trace_start(trace);
	iferr(trace);

	/* read a packet */
	trace_read_packet(trace, packet);
	/* get the layer2 headers for this packet */
	headers = trace_get_layer2_headers(packet);
	if (headers != NULL) {
		if (headers->header[0].ethertype == TRACE_ETHERTYPE_8021Q) {
			vlanhdr = ntohl(*(uint32_t *) headers->header[0].data);
			vlanid = (((vlanhdr >> 16) << 4) >> 4);
			if (vlanid != 100) {
				printf("Unexpected vlan id\n");
				error = 1;
			}
		} else {
			printf("Unexpected ethertype\n");
			error = 1;
		}

		if (headers->header[1].ethertype == TRACE_ETHERTYPE_8021Q) {
			vlanhdr = ntohl(*(uint32_t *) headers->header[1].data);
                        vlanid = (((vlanhdr >> 16) << 4) >> 4);
                        if (vlanid != 200) {
                                printf("Unexpected vlan id\n");
				error = 1;
                        }
		} else {
			printf("Unexpected ethertype\n");
			error = 1;
		}

		if (headers->header[2].ethertype != TRACE_ETHERTYPE_ARP) {
			printf("Unexpected ethertype\n");
			error = 1;
		}
		trace_destroy_layer2_headers(headers);
	}


	/* read a packet */
        trace_read_packet(trace, packet);
        /* get the layer2 headers for this packet */
        headers = trace_get_layer2_headers(packet);
        if (headers != NULL) {
		if (headers->header[0].ethertype == TRACE_ETHERTYPE_8021Q) {
                        vlanhdr = ntohl(*(uint32_t *) headers->header[0].data);
                        vlanid = (((vlanhdr >> 16) << 4) >> 4);
                        if (vlanid != 100) {
                                printf("Unexpected vlan id %u\n", vlanid);
                                error = 1;
                        }
                } else {
                        printf("Unexpected ethertype\n");
                        error = 1;
                }

                if (headers->header[1].ethertype == TRACE_ETHERTYPE_8021Q) {
                        vlanhdr = ntohl(*(uint32_t *) headers->header[1].data);
                        vlanid = (((vlanhdr >> 16) << 4) >> 4);
                        if (vlanid != 200) {
                                printf("Unexpected vlan id %u\n", vlanid);
                                error = 1;
                        }
                } else {
                        printf("Unexpected ethertype: %04x\n",
                                headers->header[1].ethertype);
                        error = 1;
                }

                if (headers->header[2].ethertype != TRACE_ETHERTYPE_ARP) {
                        printf("Unexpected ethertype: %04x\n",
                                headers->header[2].ethertype);
                        error = 1;
                }
		trace_destroy_layer2_headers(headers);
        }

	trace_destroy(trace);
	trace_destroy_packet(packet);

        if (error == 0) {
                printf("success\n");
        }

	return error;
}
