/* Program reads a trace file and counts the first octet of the source and destination
 * addresses
 */
#include "libtrace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

uint64_t srcaddrcount[256];
uint64_t dstaddrcount[256];

struct exclude_networks {
	uint32_t address;
	uint32_t mask;
	uint32_t network;
};
struct exclude_networks *exclude;
int exclude_networks_count = 0;

static void plot_results() {

	/* Push all the data into a tmp file for gnuplot */
	FILE *tmp = fopen("ipdist.tmp", "w");
        int i;
        for(i=0;i<255;i++) {
                fprintf(tmp, "%d %d %d\n", i, srcaddrcount[i], dstaddrcount[i]);
        }
        fclose(tmp);

	/* Commands that need to be sent to gnuplot */
	char *commands[] = {"set term png size 1280,960",
			    "set xrange [0:255]",
			    "set xtics 0,10,255",
			    "set output 'ipdist.png'",
			    "plot 'ipdist.tmp' using 1:2 title 'Source Address' with boxes, 'ipdist.tmp' using 1:3 title 'Destination Address' with boxes",
			    "replot"};
	/* Open pipe to gnuplot */
	FILE *gnuplot = popen("gnuplot -persistent", "w");
	/* send all commands to gnuplot */
	for(i=0;i<6;i++) {
		fprintf(gnuplot, "%s \n", commands[i]);
	}
	pclose(gnuplot);
}

/* Checks if address is part of a excluded subnet. */
static int network_excluded(uint32_t address) {

	int i;
	for(i=0;i<exclude_networks_count;i++) {
		/* Convert address into a network address */
		uint32_t net_addr = address & exclude[i].mask;

		/* If this matches the network address from the excluded list we need to exclude this
		   address. */
		if(net_addr == exclude[i].network) {
			return 1;
		}
	}

	/* If we got this far the address should not be excluded */
	return 0;
}

static void process_ip(struct sockaddr *ip, int srcaddr) {

	/* Checks if the ip is of type IPv4 */
	if (ip->sa_family == AF_INET) {

                /* IPv4 - cast the generic sockaddr to a sockaddr_in */
                struct sockaddr_in *v4 = (struct sockaddr_in *)ip;
		/* Get in_addr from sockaddr */
		struct in_addr ip4 = (struct in_addr)v4->sin_addr;
		/* Ensure the address is in network byte order */
		uint32_t address = htonl(ip4.s_addr);

		/* Check if the address is part of an excluded network.
		   This is performed before splitting the into octets so if performed over entire address. */
		if(network_excluded(address) == 0) {

			/* Split the IPv4 address into each octet */
			uint8_t octet[4];
			octet[0] = (address & 0xff000000) >> 24;
			octet[1] = (address & 0x00ff0000) >> 16;
			octet[2] = (address & 0x0000ff00) >> 8;
			octet[3] = (address & 0x000000ff);

			/* check if the supplied address was a source or destination, increment
			   the correct one */
			if(srcaddr) {
				srcaddrcount[octet[0]]++;
			} else {
				dstaddrcount[octet[0]]++;
			}
		}

        }
}

static void per_packet(libtrace_packet_t *packet) {
	struct sockaddr_storage addr;
	struct sockaddr *address;

	/* Get the source IP address */
	address = trace_get_source_address(packet, (struct sockaddr *)&addr);
	/* If a source ip address was found */
        if(address != NULL) {
                process_ip(address, 1);
        }

	/* Get the destination IP address */
	address = trace_get_destination_address(packet, (struct sockaddr *)&addr);
	/* If a destination ip address was found */
	if(address != NULL) {
		process_ip(address, 0);
	}

}

int main(int argc, char *argv[]) {

	libtrace_t *trace = NULL;
	libtrace_packet_t *packet = NULL;

	/* Ensure the input URI was supplied */
        if(argc < 2) {
                fprintf(stderr, "Usage: %s inputURI\n", argv[0]);
                return 1;
        }

	/* initialize address arrays */
        int i;
        for(i=0; i<256; i++) {
                srcaddrcount[i] = 0;
                dstaddrcount[i] = 0;
        }

	/* Setup excluded networks if any were supplied */
	exclude_networks_count = argc-2;
	exclude = malloc(sizeof(struct exclude_networks)*(argc-2));
	if(exclude == NULL) {
		fprintf(stderr, "Unable to allocate memory");
		return 1;
	}

	char delim[] = "/";
	// Convert supplied address and mask to a exclude_network structure
	for(i=2;i<argc;i++) {
		char *address = strtok(argv[i], delim);
		char *mask = strtok(NULL, delim);

		/* right shift so netmask is in network byte order */
        	exclude[i-2].mask = 0xffffffff << (32 - atoi(mask));

        	struct in_addr addr;
        	/* Convert address string into uint32_t */
        	inet_aton(address, &addr);
		/* Ensure its saved in network byte order */
        	exclude[i-2].address = htonl(addr.s_addr);

		/* Calculate the network address */
		exclude[i-2].network = exclude[i-2].address & exclude[i-2].mask;
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

	/* free memory used to hold excluded networks */
	free(exclude);

	/* Print results */
	plot_results();

	trace_destroy(trace);
	trace_destroy_packet(packet);
	//libtrace_cleanup(trace, packet);
	return 0;
}
