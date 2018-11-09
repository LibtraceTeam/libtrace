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
	/* Holds the counts of each number occurance per octet, These are cleared after every output. */
	uint64_t src[4][256];
	uint64_t dst[4][256];
	/* Maintains a running average over. Only used within the tally */
	uint64_t src_lastoutput[4][256];
	uint64_t dst_lastoutput[4][256];
	/* Holds the timestamp */
	uint64_t lastkey;
	/* Is the count of the number of packets processed, This is cleared after every output. */
	uint64_t packets;
	uint64_t output_count;
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

/* interval between outputs in seconds */
uint64_t tickrate;

static void per_tick(libtrace_t *trace, libtrace_thread_t *thread, void *global, void *tls, uint64_t tick) {

	struct addr_local *result = (struct addr_local *)malloc(sizeof(struct addr_local));
	/* Proccessing thread local storage */
	struct addr_local *local = (struct addr_local *)tls;

	/* Populate the result structure from the threads local storage and clear threads local storage*/
	int i, j;
	for(i=0;i<4;i++) {
		for(j=0;j<256;j++) {
			result->src[i][j] = local->src[i][j];
			result->dst[i][j] = local->dst[i][j];
			/* clear local storage */
			local->src[i][j] = 0;
			local->dst[i][j] = 0;
		}
	}
	result->packets = local->packets;
	local->packets = 0;

	/* Push result to the combiner */
	trace_publish_result(trace, thread, tick, (libtrace_generic_t){.ptr=result}, RESULT_USER);
}

/* Start callback function - This is run for each thread when it starts */
static void *start_callback(libtrace_t *trace, libtrace_thread_t *thread, void *global) {

        /* Create and initialize the local counter struct */
        struct addr_local *local = (struct addr_local *)malloc(sizeof(struct addr_local));
        int i, j;
        for(i=0;i<4;i++) {
		for(j=0;j<256;j++) {
			local->src[i][j] = 0;
			local->dst[i][j] = 0;
		}
        }
	local->lastkey = 0;
	local->packets = 0;

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
				int i;
				for(i=0;i<4;i++) {
					local->src[i][octet[i]] += 1;
				}
                        } else {
                                int i;
                                for(i=0;i<4;i++) {
                                        local->dst[i][octet[i]] += 1;
                                }
                        }
                }
        }
}

/* Per packet callback function run by each thread */
static libtrace_packet_t *per_packet(libtrace_t *trace, libtrace_thread_t *thread, void *global, void *tls,
        libtrace_packet_t *packet) {

        /* Regain access to the address counter structure */
        struct addr_local *local = (struct addr_local *)tls;

	/* If this is the first packet set the lastkey to the packets timestamp */
	if(local->lastkey == 0) {
		local->lastkey = trace_get_erf_timestamp(packet);
	}

	/* Increment the packet count */
	local->packets += 1;

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

	/* If this trace is not live we will manually call "per tick" */
	if(!trace_get_information(trace)->live) {
		/* get the current packets timestamp */
		uint64_t timestamp = trace_get_erf_timestamp(packet);

		/* We only want to call per_tick if we are due to output something
		 * Right shifting these converts them to seconds, tickrate is in seconds */
		if((timestamp >> 32) >= (local->lastkey >> 32) + tickrate) {
			per_tick(trace, thread, global, local, timestamp);
			local->lastkey = timestamp;
		}
	}

        /* Return the packet to libtrace */
        return packet;
}

/* Stopping callback function - When a thread closes */
static void stop_processing(libtrace_t *trace, libtrace_thread_t *thread, void *global, void *tls) {

	/* cast the local storage structure */
	struct addr_local *local = (struct addr_local *)tls;
	/* Create structure to store the result */
	struct addr_local *result = (struct addr_local *)malloc(sizeof(struct addr_local));

	/* Populate the result */
	int i, j;
	for(i=0;i<4;i++) {
		for(j=0;j<256;j++) {
			result->src[i][j] = local->src[i][j];
			result->dst[i][j] = local->dst[i][j];
		}
	}
	result->packets = local->packets;

	/* Send the final results to the combiner */
	trace_publish_result(trace, thread, 0, (libtrace_generic_t){.ptr=result}, RESULT_USER);

	/* Cleanup the local storage */
	free(local);
}

/* Starting callback for reporter thread */
static void *start_reporter(libtrace_t *trace, libtrace_thread_t *thread, void *global) {
        /* Create tally structure */
        struct addr_local *tally = (struct addr_local *)malloc(sizeof(struct addr_local));

        /* Initialize the tally structure */
        int i, j;
        for(i=0;i<4;i++) {
		for(j=0;j<256;j++) {
                	tally->src[i][j] = 0;
                	tally->dst[i][j] = 0;
			tally->src_lastoutput[i][j] = 0;
			tally->dst_lastoutput[i][j] = 0;
		}
        }
	tally->lastkey = 0;
	tally->packets = 0;
	tally->output_count = 0;

        return tally;
}

static void plot_results(struct addr_local *tally, uint64_t tick) {

	char outputfile[255];
	char outputplot[255];
	snprintf(outputfile, sizeof(outputfile), "ipdist-%u.data", tick);
	snprintf(outputplot, sizeof(outputplot), "ipdist-%u.png", tick);

	/* Push all data into data file */
	FILE *tmp = fopen(outputfile, "w");
        int i, j;
	fprintf(tmp, "#Hits\t\t\t\t\t\t\t\t\tPercentage Change\n");
	fprintf(tmp, "#num\toctet1\t\toctet2\t\toctet3\t\toctet4\t\toctet1\t\toctet2\t\toctet3\t\toctet4\n");
	fprintf(tmp, "#\tsrc\tdst\tsrc\tdst\tsrc\tdst\tsrc\tdst\tsrc\tdst\tsrc\tdst\tsrc\tdst\tsrc\tdst\n");
        for(i=0;i<256;i++) {
		fprintf(tmp, "%d", i);
		for(j=0;j<4;j++) {
			fprintf(tmp, "\t%d\t%d", tally->src[j][i], tally->dst[j][i]);
		}

		/* Calculates the percentage change from the last output */
		for(j=0;j<4;j++) {
			float src_inc = 0;
			float dst_inc = 0;
			if(tally->src[j][i] != 0) {
				src_inc = (((float)tally->src[j][i] - (float)tally->src_lastoutput[j][i]) / (float)tally->src[j][i]) * 100;
			}
			if(tally->dst[j][i] != 0) {
				dst_inc = (((float)tally->dst[j][i] - (float)tally->dst_lastoutput[j][i]) / (float)tally->dst[j][i]) * 100;
			}
			fprintf(tmp, "\t%.0f\t%.0f", src_inc, dst_inc);
		}

		fprintf(tmp, "\n");
        }
        fclose(tmp);
	printf("Ouput data file %s and plot %s\n", outputfile, outputplot);

        /* Open pipe to gnuplot */
        FILE *gnuplot = popen("gnuplot -persistent", "w");
        /* send all commands to gnuplot */
        fprintf(gnuplot, "set term png size 1280,960 \n");
	fprintf(gnuplot, "set title 'IP Distribution'\n");
	fprintf(gnuplot, "set xrange[0:255]\n");
	fprintf(gnuplot, "set xlabel 'Prefix'\n");
	fprintf(gnuplot, "set ylabel 'Hits'\n");
	fprintf(gnuplot, "set y2label 'Percentage Change'\n");
	fprintf(gnuplot, "set xtics 0,10,255\n");
	fprintf(gnuplot, "set y2range[-100:100]\n");
	//fprintf(gnuplot, "set ytics nomirror\n");
	//fprintf(gnuplot, "set y2tics\n");
	//fprintf(gnuplot, "set tics out\n");
	fprintf(gnuplot, "set output '%s'\n", outputplot);
	fprintf(gnuplot, "plot '%s' using 1:2 title 'Source octet 1' axes x1y1 with boxes,", outputfile);
	fprintf(gnuplot, "'%s' using 1:3 title 'Destination octet 1' axes x1y1 with boxes,", outputfile);
	//fprintf(gnuplot, "'%s' using 1:4 title 'Source octet 2' axes x1y1 with boxes,", outputfile);
	//fprintf(gnuplot, "'%s' using 1:5 title 'Destination octet 2' axes x1y1 with boxes,", outputfile);
	//fprintf(gnuplot, "'%s' using 1:6 title 'Source octet 3' axes x1y1 with boxes,", outputfile);
	//fprintf(gnuplot, "'%s' using 1:7 title 'Destination octet 3' axes x1y1 with boxes,", outputfile);
	//fprintf(gnuplot, "'%s' using 1:8 title 'Source octet 4' axes x1y1 with boxes,", outputfile);
	//fprintf(gnuplot, "'%s' using 1:9 title 'Destination octet 4' axes x1y1 with boxes,", outputfile);
	fprintf(gnuplot, "'%s' using 1:10 title 'Octet 1 source change' axes x1y2 with lines,", outputfile);
	fprintf(gnuplot, "'%s' using 1:11 title 'Octet 1 destination change' axes x1y2 with lines\n", outputfile);
	//fprintf(gnuplot, "'%s' using 1:12 title 'Octet 2 source change' axes x1y2 with lines,", outputfile);
	//fprintf(gnuplot, "'%s' using 1:13 title 'Octet 2 destination change' axes x1y2 with lines,", outputfile);
	//fprintf(gnuplot, "'%s' using 1:14 title 'Octet 3 source change' axes x1y2 with lines,", outputfile);
	//fprintf(gnuplot, "'%s' using 1:15 title 'Octet 3 destination change' axes x1y2 with lines,", outputfile);
	//fprintf(gnuplot, "'%s' using 1:16 title 'Octet 4 source change' axes x1y2 with lines,", outputfile);
	//fprintf(gnuplot, "'%s' using 1:17 title 'Octet 4 destination change' axes x1y2 with lines\n", outputfile);
	fprintf(gnuplot, "replot");
        pclose(gnuplot);
}


/* Callback when a result is given to the reporter thread */
static void per_result(libtrace_t *trace, libtrace_thread_t *sender, void *global,
        void *tls, libtrace_result_t *result) {

        struct addr_local *results;
        struct addr_local *tally;
	uint64_t key;

        /* We only want to handle results containing our user-defined structure  */
        if(result->type != RESULT_USER) {
                return;
        }

        /* This key is the key that was passed into trace_publish_results
	 * this will contain the erf timestamp for the packet */
        key = result->key;

        /* result->value is a libtrace_generic_t that was passed into trace_publish_results() */
        results = (struct addr_local *)result->value.ptr;

        /* Grab our tally out of thread local storage */
        tally = (struct addr_local *)tls;

	/* Add all the results to the tally */
	int i, j;
	for(i=0;i<4;i++) {
		for(j=0;j<256;j++) {
			tally->src[i][j] += results->src[i][j];
			tally->dst[i][j] += results->dst[i][j];
		}
	}
	tally->packets += results->packets;

	/* If the current timestamp is greater than the last printed plus the interval, output a result */
	if((key >> 32) >= (tally->lastkey >> 32) + tickrate) {

		/* update last key */
                tally->lastkey = key;

		/* Need to initialise lastoutput values on first pass */
		if(tally->output_count == 0) {
			for(i=0;i<4;i++) {
				for(j=0;j<256;j++) {
					tally->src_lastoutput[i][j] = tally->src[i][j];
                        	        tally->dst_lastoutput[i][j] = tally->dst[i][j];
				}
			}
		}

		/* Plot the result with the key in epoch seconds*/
                plot_results(tally, key >> 32);

		/* increment the output counter */
		tally->output_count++;

                /* clear the tally but copy old values over first*/
                for(i=0;i<4;i++) {
			for(j=0;j<256;j++) {
				tally->src_lastoutput[i][j] = tally->src[i][j];
				tally->dst_lastoutput[i][j] = tally->dst[i][j];
                        	tally->src[i][j] = 0;
                        	tally->dst[i][j] = 0;
			}
                }
		tally->packets = 0;
        }

        /* Cleanup the thread results */
        free(results);
}

/* Callback when the reporter thread stops (essentially when the program ends) */
static void stop_reporter(libtrace_t *trace, libtrace_thread_t *thread, void *global, void *tls) {

        /* Get the tally from the thread local storage */
        struct addr_local *tally = (struct addr_local *)tls;

	/* If there is any remaining data in the tally plot it */
	if(tally->packets > 0) {
		plot_results(tally, (tally->lastkey >> 32) + 1);
	}
	/* Cleanup tally results*/
	free(tally);
}

static void libtrace_cleanup(libtrace_t *trace, libtrace_callback_set_t *processing,
	libtrace_callback_set_t *reporting) {
	/* Only destroy if the structure exists */
	if(trace) {
		trace_destroy(trace);
	}
	if(processing) {
		trace_destroy_callback_set(processing);
	}
	if(reporting) {
		trace_destroy_callback_set(reporting);
	}
}

/* Converts a string representation eg 1.2.3.4/24 into a network structure */
static int get_network(char *network_string, struct network *network) {

	char delim[] = "/";
	/* Split the address and mask portion of the string */
	char *address = strtok(network_string, delim);
	char *mask = strtok(NULL, delim);

	/* Check the subnet mask is valid */
	if(atoi(mask) == 0 || atoi(mask) > 32 || atoi(mask) < 0) {
		return 1;
        }
        /* right shift so netmask is in network byte order */
        network->mask = 0xffffffff << (32 - atoi(mask));

        struct in_addr addr;
        /* Convert address string into uint32_t and check its valid */
        if(inet_aton(address, &addr) == 0) {
        	return 2;
        }
        /* Ensure its saved in network byte order */
        network->address = htonl(addr.s_addr);

       	/* Calculate the network address */
        network->network = network->address & network->mask;

	return 0;
}

int main(int argc, char *argv[]) {

	libtrace_t *trace;
	/* Callbacks for processing and reporting threads */
	libtrace_callback_set_t *processing, *reporter;


	/* Ensure the input URI was supplied */
        if(argc < 3) {
                fprintf(stderr, "Usage: %s inputURI [outputInterval (Seconds)] [excluded networks]\n", argv[0]);
                fprintf(stderr, "       eg. ./ipdist input.erf 60 210.10.3.0/24 70.5.0.0/16\n");
                return 1;
        }
	/* Convert tick into an int */
	tickrate = atoi(argv[2]);


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

	/* Set the tick interval only if this is a live capture */
	if(trace_get_information(trace)->live) {
		/* tickrate is in seconds but tick_interval expects milliseconds */
		trace_set_tick_interval(trace, tickrate*1000);
	}
	/* Do not buffer the reports */
	trace_set_reporter_thold(trace, 1);


	/* Setup excluded networks if any were supplied */
	struct exclude_networks *exclude = malloc(sizeof(struct exclude_networks));
	exclude->networks = malloc(sizeof(struct network)*(argc-3));
	if(exclude == NULL || exclude->networks == NULL) {
		fprintf(stderr, "Unable to allocate memory");
		libtrace_cleanup(trace, processing, reporter);
		return 1;
	}
	exclude->count = 0;
	int i;
	for(i=0;i<argc-3;i++) {
		/* convert the network string into a network structure */
		if(get_network(argv[i+3], &exclude->networks[i]) != 0) {
			fprintf(stderr, "Error creating excluded network");
			return 1;
		}
		/* increment the count of excluded networks */
		exclude->count += 1;
	}


	/* Start the trace, if it errors return */
	if(trace_pstart(trace, exclude, processing, reporter)) {
		trace_perror(trace, "Starting parallel trace");
		libtrace_cleanup(trace, processing, reporter);
		return 1;
	}

	/* This will wait for all threads to complete */
	trace_join(trace);

	/* Clean up everything */
	free(exclude->networks);
	free(exclude);
	libtrace_cleanup(trace, processing, reporter);

	return 0;
}
