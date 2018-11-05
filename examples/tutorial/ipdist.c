/* Program reads a trace file and counts the first octet of the source and destination
 * addresses
 */
#include "libtrace.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

uint64_t srcaddrcount[255];
uint64_t dstaddrcount[255];

static void print_results() {
	int i;
	/* Print results */
        printf("Source addresses\n");
        for(i=0;i<255;i++) {
                printf("%d ", srcaddrcount[i]);
        }
        printf("\n");

        printf("Destination addresses\n");
        for(i=0;i<255;i++) {
                printf("%d ", dstaddrcount[i]);
        }
        printf("\n");
}

static void print_results2() {
	int i, j;
	printf("Source addresses\n");
	for(i=0;i<255;i++) {
		for(j=0;j<srcaddrcount[i];j++) {
			printf(".");
		}
		printf("\n");
	}
	printf("Destination addresses\n");
        for(i=0;i<255;i++) {
                for(j=0;j<dstaddrcount[i];j++) {
                        printf(".");
                }
                printf("\n");
        }
}

static void process_ip(struct sockaddr *ip, int srcaddr) {

	/* Checks if the ip is of type IPv4 */
	if (ip->sa_family == AF_INET) {

                /* IPv4 - cast the generic sockaddr to a sockaddr_in */
                struct sockaddr_in *v4 = (struct sockaddr_in *)ip;
		/* Get in_addr from sockaddr */
		struct in_addr ip4 = (struct in_addr)v4->sin_addr;
		/* Split the IPv4 address into each octet */
		uint8_t octet[4];
		octet[0] = (ip4.s_addr & 0x000000ff);
		octet[1] = (ip4.s_addr & 0x0000ff00) >> 8;
		octet[2] = (ip4.s_addr & 0x00ff0000) >> 16;
		octet[3] = (ip4.s_addr & 0xff000000) >> 24;
		//printf("%u.%u.%u.%u\n", octets[0], octets[1], octets[2], octets[3]);

		/* check if the supplied address was a source or destination, increment
		   the correct one */
		if(srcaddr) {
			srcaddrcount[octet[0]]++;
		} else {
			dstaddrcount[octet[0]]++;
		}

        }
}

static void per_packet(libtrace_packet_t *packet) {
	struct sockaddr_storage addr;
	struct sockaddr *addr_src;
	struct sockaddr *addr_dst;

	/* Get the source IP address */
	addr_src = trace_get_source_address(packet, (struct sockaddr *)&addr);
	/* If a source ip address was found */
        if(addr_src != NULL) {
                process_ip(addr_src, 1);
        }

	/* Get the destination IP address */
	addr_dst = trace_get_destination_address(packet, (struct sockaddr *)&addr);
	/* If a destination ip address was found */
	if(addr_dst != NULL) {
		process_ip(addr_dst, 0);
	}

}

int main(int argc, char *argv[]) {

	libtrace_t *trace = NULL;
	libtrace_packet_t *packet = NULL;

	/* initialize address arrays */
	int i;
	for(i=0; i<255; i++) {
		srcaddrcount[i] = 0;
		dstaddrcount[i] = 0;
	}

	/* Ensure the input URI was supplied */
	if(argc < 2) {
		fprintf(stderr, "Usage: %s inputURI\n", argv[0]);
		return 1;
	}

	/* Create the packet structure */
	packet = trace_create_packet();

	/* Create the trace */
	trace = trace_create(argv[1]);

	/* Ensure no error has occured creating the trace */
	if(trace_is_err(trace)) {
		trace_perror(trace, "Opening trace file");
		return 1;
	}

	/* Start the trace, if it errors return */
	if(trace_start(trace) == -1) {
		trace_perror(trace, "Starting trace");
		trace_destroy(trace);
		return 1;
	}

	/* Proccess each packet in the trace */
	while(trace_read_packet(trace,packet)>0) {
		per_packet(packet);
	}

	/* If trace is error after proccessing packets it failed to process
	   the entire trace */
	if(trace_is_err(trace)) {
		trace_perror(trace, packet);
		return 1;
	}

	/* Print results */
	print_results();

	trace_destroy(trace);
	trace_destroy_packet(packet);
	//libtrace_cleanup(trace, packet);
	return 0;
}
