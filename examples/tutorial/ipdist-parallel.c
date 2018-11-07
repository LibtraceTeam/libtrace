/* Program reads a trace file and counts the first octet of the source and destination
 * address and plots them on a graph using gnuplot.
 */
#include "libtrace_parallel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

/* Structure to hold the counters each thread has its own one of these */
struct addr_local {
	uint64_t src[256];
	uint64_t dst[256];
};
/* Structure to hold the result from a processing thread */
struct addr_result {
	uint64_t src[256];
	uint64_t dst[256];
};
/* Structure to hold counters the report has one of these, it combines
 * the the counters of each threads local storage used by the reporter thread */
struct addr_tally {
	uint64_t src[256];
	uint64_t dst[256];
	uint64_t lastkey;
};

/* Structure to hold excluded networks */
struct exclude_networks {
	int count;
	struct network *networks;
};
struct network {
	uint32_t address;
	uint32_t mask;
	uint32_t network;
};

/* Start callback function - This is run for each thread when it starts */
static void *start_callback(libtrace_t *trace, libtrace_thread_t *thread, void *global) {

        /* Create and initialize the local counter struct */
        struct addr_local *local = (struct addr_local *)malloc(sizeof(struct addr_local));
        int i;
        for(i=0;i<256;i++) {
                local->src[i] = 0;
                local->dst[i] = 0;
        }

        /* return the local storage so it is available for all other callbacks for the thread*/
        return local;
}

/* Checks if address is part of a excluded subnet. */
static int network_excluded(uint32_t address, struct exclude_networks *exclude) {

        int i;
        for(i=0;i<exclude->count;i++) {
                /* Convert address into a network address */
                uint32_t net_addr = address & exclude->networks[i].mask;

                /* If this matches the network address from the excluded list we need to exclude this
                   address. */
                if(net_addr == exclude->networks[i].network) {
                        return 1;
                }
        }

        /* If we got this far the address should not be excluded */
        return 0;
}

static void process_ip(struct sockaddr *ip, struct addr_local *local, struct exclude_networks *exclude, int srcaddr) {

        /* Checks if the ip is of type IPv4 */
        if (ip->sa_family == AF_INET) {

                /* IPv4 - cast the generic sockaddr to a sockaddr_in */
                struct sockaddr_in *v4 = (struct sockaddr_in *)ip;
                /* Get in_addr from sockaddr */
                struct in_addr ip4 = (struct in_addr)v4->sin_addr;
                /* Ensure the address is in network byte order */
                uint32_t address = htonl(ip4.s_addr);

                /* Check if the address is part of an excluded network. */
                if(network_excluded(address, exclude) == 0) {

                        /* Split the IPv4 address into each octet */
                        uint8_t octet[4];
                        octet[0] = (address & 0xff000000) >> 24;
                        octet[1] = (address & 0x00ff0000) >> 16;
                        octet[2] = (address & 0x0000ff00) >> 8;
                        octet[3] = (address & 0x000000ff);

                        /* check if the supplied address was a source or destination,
                           increment the correct one */
                        if(srcaddr) {
                                local->src[octet[0]]++;
                        } else {
                                local->dst[octet[0]]++;
                        }
                }
        }
}

/* Per packet callback function run by each thread */
static libtrace_packet_t *per_packet(libtrace_t *trace, libtrace_thread_t *thread, void *global, void *tls,
        libtrace_packet_t *packet) {

        /* Regain access to the address counter structure */
        struct addr_local *local = (struct addr_local *)tls;

	/* Regain access to excluded networks pointer */
	struct exclude_networks *exclude = (struct exclude_networks *)global;

        struct sockaddr_storage addr;
        struct sockaddr *ip;

        /* Get the source IP address */
        ip = trace_get_source_address(packet, (struct sockaddr *)&addr);
        /* If a source ip address was found */
        if(ip != NULL) {
                process_ip(ip, local, exclude, 1);
        }

        /* Get the destination IP address */
        ip = trace_get_destination_address(packet, (struct sockaddr *)&addr);
        /* If a destination ip address was found */
        if(ip != NULL) {
                process_ip(ip, local, exclude, 0);
        }

        /* Return the packet to libtrace */
        return packet;
}

/* Stopping callback function */
static void stop_processing(libtrace_t *trace, libtrace_thread_t *thread, void *global, void *tls) {

	/* create a structure to hold the result from the processing thread */
	struct addr_result *result = (struct addr_result *)malloc(sizeof(struct addr_result));
	/* cast the local storage structure */
	struct addr_local *local = (struct addr_local *)tls;

	/* Populate the result structure */
	int i;
	for(i=0;i<256;i++) {
		result->src[i] = local->src[i];
		result->dst[i] = local->dst[i];
	}

	/* Publish the result to the reporter thread */
	trace_publish_result(trace, thread, 0, (libtrace_generic_t){.ptr=result}, RESULT_USER);

	/* Cleanup the local storage */
	free(local);
}




/* Starting callback for reporter thread */
static void *start_reporter(libtrace_t *trace, libtrace_thread_t *thread, void *global) {
        /* Create tally structure */
        struct addr_tally *tally = (struct addr_tally *)malloc(sizeof(struct addr_tally));

        /* Initialize the tally structure */
        int i;
        for(i=0;i<256;i++) {
                tally->src[i] = 0;
                tally->dst[i] = 0;
        }
	tally->lastkey = 0;

        return tally;
}

static void plot_results(struct addr_tally *tally) {

        /* Get the current time */
        time_t current_time = time(NULL);
        char* time_string = ctime(&current_time);

        /* Push all the data into a tmp file for gnuplot */
	char outputfile[255];
	char outputplot[255];
	snprintf(outputfile, sizeof(outputfile), "ipdist-%u.data", current_time);
	snprintf(outputplot, sizeof(outputplot), "ipdist-%u.png", current_time);
        FILE *tmp = fopen(outputfile, "w");
        int i;
        for(i=0;i<255;i++) {
                fprintf(tmp, "%d %d %d\n", i, tally->src[i], tally->dst[i]);
        }
        fclose(tmp);

        /* Open pipe to gnuplot */
        FILE *gnuplot = popen("gnuplot -persistent", "w");
        /* send all commands to gnuplot */
        fprintf(gnuplot, "set term png size 1280,960 \n");
	fprintf(gnuplot, "set title 'IP Distribution'\n");
	fprintf(gnuplot, "set xrange[0:255]\n");
	fprintf(gnuplot, "set xlabel 'Prefix'\n");
	fprintf(gnuplot, "set xlabel 'Hits'\n");
	fprintf(gnuplot, "set xtics 0,10,255\n");
	fprintf(gnuplot, "set output '%s'\n", outputplot);
	fprintf(gnuplot, "plot '%s' using 1:2 title 'Source address' with boxes, '%s' using 1:3 title 'Destination address' with boxes\n", outputfile, outputfile);
        pclose(gnuplot);
}


/* Callback when a result is given to the reporter thread */
static void per_result(libtrace_t *trace, libtrace_thread_t *sender, void *global,
        void *tls, libtrace_result_t *result) {

        struct addr_result *results;
        uint64_t key;
        struct addr_tally *tally;

        /* We only want to handle results containing our user-defined structure  */
        if(result->type != RESULT_USER) {
                return;
        }

        /* This key is the key that was passed into trace_publish_results */
        key = result->key;

        /* result->value is a libtrace_generic_t that was passed into trace_publish_results() */
        results = (struct addr_result *)result->value.ptr;

        /* Grab our tally out of thread local storage */
        tally = (struct addr_tally *)tls;
	/* increment tally with the new results */
        int i;
        for(i=0;i<256;i++) {
                tally->src[i] += results->src[i];
                tally->dst[i] += results->dst[i];
                tally->lastkey = key;
        }

	/* Plot the result */
	plot_results(tally);

        /* Cleanup the thread results */
        free(results);
}

/* Callback when the reporter thread stops (essentially when the program ends) */
static void stop_reporter(libtrace_t *trace, libtrace_thread_t *thread, void *global, void *tls) {

        /* Get the tally from the thread local storage */
        struct addr_tally *tally = (struct addr_tally *)tls;

        //OUTPUT DATA
	//plot_results(tally);

	/* Cleanup tally results*/
	free(tally);
}

static void per_tick(libtrace_t *trace, libtrace_thread_t *thread, void *global, void *tls, uint64_t tick) {

	struct addr_result *result = (struct addr_result *)malloc(sizeof(struct addr_result));
	struct addr_local *local = (struct addr_local *)tls;

	/* Populate the result structure from the threads local storage and clear threads local storage*/
	int i;
	for(i=0;i<256;i++) {
		/* Populate results */
		result->src[i] = local->src[i];
		result->dst[i] = local->dst[i];
		/* Clear local storage */
		local->src[i] = 0;
		local->dst[i] = 0;
	}

	printf("tick: %u\n", tick);

	/* Push the result to the combiner */
	trace_publish_result(trace, thread, tick, (libtrace_generic_t){.ptr=result}, RESULT_USER);
}

int main(int argc, char *argv[]) {

	libtrace_t *trace;
	/* Callbacks for processing and reporting threads */
	libtrace_callback_set_t *processing, *reporter;

	/* Ensure the input URI was supplied */
        if(argc < 3) {
                fprintf(stderr, "Usage: %s inputURI outputInterval [excluded networks]\n", argv[0]);
                fprintf(stderr, "       eg. ./ipdist input.erf 10000 210.10.3.0/24 70.5.0.0/16\n");
                return 1;
        }
	/* Convert tick into correct format */
	uint64_t tickrate = atoi(argv[2]);

	/* Create the trace */
        trace = trace_create(argv[1]);
        /* Ensure no error has occured creating the trace */
        if(trace_is_err(trace)) {
                trace_perror(trace, "Creating trace");
                return 1;
        }

	/* Setup the processing threads */
	processing = trace_create_callback_set();
	trace_set_starting_cb(processing, start_callback);
	trace_set_packet_cb(processing, per_packet);
	trace_set_stopping_cb(processing, stop_processing);
	trace_set_tick_interval_cb(processing, per_tick);
	/* Setup the reporter threads */
	reporter = trace_create_callback_set();
	trace_set_starting_cb(reporter, start_reporter);
	trace_set_result_cb(reporter, per_result);
	trace_set_stopping_cb(reporter, stop_reporter);

	/* Parallel specific configuration MUST BE PERFORMED AFTER TRACE IS CREATED */
	trace_set_perpkt_threads(trace, 4);
	/* Order the results by timestamp */
	trace_set_combiner(trace, &combiner_ordered, (libtrace_generic_t){0});
	/* Try to balance the load across all processing threads */
	trace_set_hasher(trace, HASHER_BALANCE, NULL, NULL);
	/* Set the tick interval */
	trace_set_tick_interval(trace, tickrate);



	/* Setup excluded networks if any were supplied */
	struct exclude_networks *exclude = malloc(sizeof(struct exclude_networks));
	exclude->networks = malloc(sizeof(struct network)*(argc-3));
	if(exclude == NULL || exclude->networks == NULL) {
		fprintf(stderr, "Unable to allocate memory");
		return 1;
	}
	exclude->count = 0;

	char delim[] = "/";
	int i;
	for(i=0;i<argc-3;i++) {
		char *address = strtok(argv[i+3], delim);
		char *mask = strtok(NULL, delim);

		/* Check the subnet mask is valid */
		if(atoi(mask) == 0 || atoi(mask) > 32 || atoi(mask) < 0) {
			fprintf(stderr, "Invalid subnet mask: %s\n", mask);
                        return 1;
		}
		/* right shift so netmask is in network byte order */
        	exclude->networks[i].mask = 0xffffffff << (32 - atoi(mask));

        	struct in_addr addr;
        	/* Convert address string into uint32_t and check its valid */
        	if(inet_aton(address, &addr) == 0) {
			fprintf(stderr, "Invalid exclude address: %s\n", address);
			return 1;
		}
		/* Ensure its saved in network byte order */
        	exclude->networks[i].address = htonl(addr.s_addr);

		/* Calculate the network address */
		exclude->networks[i].network = exclude->networks[i].address & exclude->networks[i].mask;

		/* Increment counter of excluded networks */
		exclude->count += 1;
	}

	/* Start the trace, if it errors return */
	if(trace_pstart(trace, exclude, processing, reporter)) {
		trace_perror(trace, "Starting parallel trace");
		return 1;
	}

	/* This will wait for all threads to complete */
	trace_join(trace);

	/* Clean up everything */
	free(exclude->networks);
	free(exclude);
	trace_destroy(trace);
	trace_destroy_callback_set(processing);
	trace_destroy_callback_set(reporter);

	return 0;
}
