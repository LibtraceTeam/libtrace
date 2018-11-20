#include "libtrace_parallel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>
#include <getopt.h>

/* Structure to hold the counters each thread has its own one of these */
struct addr_local {
	/* Holds the counts of each number occurance per octet, These are cleared after every output. */
	uint64_t src[4][256];
	uint64_t dst[4][256];
	/* Holds the results from the previous output */
	uint64_t src_lastoutput[4][256];
	uint64_t dst_lastoutput[4][256];
	/* Holds the timestamp */
	uint64_t lastkey;
	/* Is the count of the number of packets processed, This is cleared after every output. */
	uint64_t packets;
	/* Total number an output has been generated */
	uint64_t output_count;
	/* Pointer to stats structure */
	struct addr_stats *stats;
	uint64_t lost_packets;
};
struct addr_stats {
	/* Holds the percentage change compared to the previous output */
	float src[4][256];
	float dst[4][256];
	/* Stats calculated independently per output */
	double mode_src[4];
	double mode_dst[4];
	double mean_src[4];
	double mean_dst[4];
	double median_src[4];
	double median_dst[4];
	double stddev_src[4];
	double stddev_dst[4];
	double variance_src[4];
	double variance_dst[4];
	double skewness_src[4];
	double skewness_dst[4];
	struct addr_rank *rank_src[4];
	struct addr_rank *rank_dst[4];
};
struct addr_rank {
	uint8_t addr;
	/* count is the priority */
	uint64_t count;
	/* pointer to next ranking item */
	struct addr_rank* next;
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

uint64_t tickrate;
char *stats_outputdir = "";

/*************************************************************************
Priority queue linked list */

static struct addr_rank *rank_new(uint8_t addr, uint64_t count) {
	struct addr_rank *tmp = malloc(sizeof(struct addr_rank));
	tmp->addr = addr;
	tmp->count = count;
	tmp->next = NULL;

	return tmp;
}
static uint8_t peak(struct addr_rank **head) {
        return (*head)->addr;
}
static uint64_t peak_count(struct addr_rank **head) {
	return (*head)->count;
}
static void pop(struct addr_rank **head) {
	struct addr_rank* tmp = *head;
	(*head) = (*head)->next;
	free(tmp);
}
static void push(struct addr_rank **head, uint8_t addr, uint64_t count) {
	struct addr_rank *curr = (*head);
	struct addr_rank *tmp = rank_new(addr, count);

	/* Check if the new node has a greater priority than the head */
	if((*head)->count < count) {
		tmp->next = *head;
		(*head) = tmp;
	} else {
		/* Jump through the list until we find the correct position */
		while (curr->next != NULL && curr->next->count > count) {
			curr = curr->next;
		}

		tmp->next = curr->next;
		curr->next = tmp;
	}
}
/*************************************************************************/


static void compute_stats(struct addr_local *tally) {
	int i, j, k;

	/* To get ranking we push everything into the priority queue at pop things off 1 by one which returns them in high to lowest priority */
	for(i=0;i<4;i++) {
		tally->stats->rank_src[i] = rank_new(0, tally->src[i][0]);
		tally->stats->rank_dst[i] = rank_new(0, tally->dst[i][0]);
		for(j=1;j<256;j++) {
			/* Push everything into the priority queue
			 * each item will be popped off in the correct order */
			push(&tally->stats->rank_src[i], j, tally->src[i][j]);
			push(&tally->stats->rank_dst[i], j, tally->dst[i][j]);
		}
	}

	/* Calculate mean, variance and standard deviation */
	for(k=0;k<4;k++) {

		double ex = 0;
	        double ex2 = 0;
	        double n = 0;
	        double m = 0;
		for(i=0;i<256;i++) {
			for(j=0;j<tally->src[k][i];j++) {
				if(n == 0) {
					m = i;
				}
				n += 1;
				ex += (i - m);
				ex2 += ((i - m) * (i - m));
			}
		}
		// tally->stats->mean_src[k] = (k + (ex / n));
		tally->stats->mean_src[k] = (m + (ex / n));
		tally->stats->variance_src[k] = ((ex2 - (ex*ex)/n) / n);
		tally->stats->stddev_src[k] = sqrt(tally->stats->variance_src[k]);

		ex = 0;
		ex2 = 0;
		n = 0;
		m = 0;
		for(i=0;i<256;i++) {
                        for(j=0;j<tally->dst[k][i];j++) {
                                if(n == 0) {
                                        m = i;
                                }
                                n += 1;
                                ex += (i - m);
                                ex2 += ((i - m) * (i - m));
                        }
                }
		// tally->stats->mean_dst[k] = (k + (ex / n));
		tally->stats->mean_dst[k] = (m + (ex / n));
                tally->stats->variance_dst[k] = ((ex2 - (ex*ex)/n) / n);
                tally->stats->stddev_dst[k] = sqrt(tally->stats->variance_dst[k]);

		/* Get the median */
		int c = (n/2) - tally->src[k][0];
		int c2 = 0;
		while(c > 0) {
			c2 += 1;
			c -= tally->src[k][c2];
		}
		tally->stats->median_src[k] = c2;
		c = (n/2) - tally->dst[k][0];
		c2 = 0;
		while(c > 0) {
			c2 += 1;
			c -= tally->dst[k][c2];
		}
		tally->stats->median_dst[k] = c2;

		/* Get the mode which is the first item in the priority queue */
		tally->stats->mode_src[k] = peak(&tally->stats->rank_src[k]);
		tally->stats->mode_dst[k] = peak(&tally->stats->rank_src[k]);

		/* Calculate skewness */
                tally->stats->skewness_src[k] = (tally->stats->mean_src[k] - tally->stats->median_src[k]) / tally->stats->stddev_src[k];
                tally->stats->skewness_dst[k] = (tally->stats->mean_dst[k] - tally->stats->median_dst[k]) / tally->stats->stddev_dst[k];
	}

}

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
	tally->stats = malloc(sizeof(struct addr_stats));

        /* Initialize the tally structure */
        int i, j;
        for(i=0;i<4;i++) {
		for(j=0;j<256;j++) {
                	tally->src[i][j] = 0;
                	tally->dst[i][j] = 0;
			tally->src_lastoutput[i][j] = 0;
			tally->dst_lastoutput[i][j] = 0;
			tally->stats->src[i][j] = 0;
			tally->stats->dst[i][j] = 0;
		}
		/* Stats related varibles */
		tally->stats->mode_src[i] = 0;
		tally->stats->mode_dst[i] = 0;
		tally->stats->mean_src[i] = 0;
		tally->stats->mean_dst[i] = 0;
		tally->stats->median_src[i] = 0;
		tally->stats->median_dst[i] = 0;
		tally->stats->stddev_src[i] = 0;
		tally->stats->stddev_dst[i] = 0;
		tally->stats->variance_src[i] = 0;
		tally->stats->variance_dst[i] = 0;
		tally->stats->skewness_src[i] = 0;
		tally->stats->skewness_dst[i] = 0;
        }
	tally->lost_packets = 0;
	tally->lastkey = 0;
	tally->packets = 0;
	tally->output_count = 0;

        return tally;
}

static void output_results(struct addr_local *tally, uint64_t tick) {

	int i, j;

	/* Calculations before reporting the results */
	/* Need to initialise lastoutput values on first pass,
	 * this is so we have a base line for percentage changed */
        if(tally->output_count == 0) {
                for(i=0;i<4;i++) {
                       	for(j=0;j<256;j++) {
                                tally->src_lastoutput[i][j] = tally->src[i][j];
                        	tally->dst_lastoutput[i][j] = tally->dst[i][j];
                	}
        	}
         }
	/* Compute the stats */
        compute_stats(tally);

	/* Finaly output the results */
	printf("Generating output \"%s/ipdist-%lu\" Packets lost: %lu\n", stats_outputdir, tick, tally->lost_packets);

	/* Output the results */
	char outputfile[255];
	snprintf(outputfile, sizeof(outputfile), "%s/ipdist-%lu.data", stats_outputdir, tick);
	FILE *tmp = fopen(outputfile, "w");
	fprintf(tmp, "#time\t\trank\toctet1\t\t\t\toctet2\t\t\t\toctet3\t\t\t\toctet4\n");
	fprintf(tmp, "#\t\t\tsrc\thits\tdst\thits\tsrc\thits\tdst\thits\tsrc\thits\tdst\thits\tsrc\thits\tdst\thits\n");
	for(i=0;i<256;i++) {
		fprintf(tmp, "%lu\t%d", tick, i+1);
		for(j=0;j<4;j++) {
			/* Get the highest ranking to lowest ranking octets */
			fprintf(tmp, "\t%u", peak(&tally->stats->rank_src[j]));
			fprintf(tmp, "\t%lu", peak_count(&tally->stats->rank_src[j]));
			fprintf(tmp, "\t%u", peak(&tally->stats->rank_dst[j]));
			fprintf(tmp, "\t%lu", peak_count(&tally->stats->rank_dst[j]));
			pop(&tally->stats->rank_src[j]);
			pop(&tally->stats->rank_dst[j]);
		}
		fprintf(tmp, "\n");
	}
	fclose(tmp);

	char outputfile_stats[255];
	snprintf(outputfile_stats, sizeof(outputfile_stats), "%s/ipdist-%lu.stats", stats_outputdir, tick);
	tmp = fopen(outputfile_stats, "w");
	/* append stats data to end of file */
	fprintf(tmp, "#\tmean\tstddev\tvariance\tmedian\tmode\tskewness\n");
	for(i=0;i<4;i++) {
		fprintf(tmp, "src%d\t%0.f\t%0.f\t%0.f\t\t%0.f\t%0.f\t%f\n", i+1, tally->stats->mean_src[i], tally->stats->stddev_src[i], tally->stats->variance_src[i], tally->stats->median_src[i], tally->stats->mode_src[i], tally->stats->skewness_src[i]);
		fprintf(tmp, "dst%d\t%0.f\t%0.f\t%0.f\t\t%0.f\t%0.f\t%f\n", i+1, tally->stats->mean_dst[i], tally->stats->stddev_dst[i], tally->stats->variance_dst[i], tally->stats->median_src[i], tally->stats->mode_dst[i], tally->stats->skewness_dst[i]);
		fprintf(tmp, "\n\n");
	}
        fclose(tmp);
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

	/* Increment lost packets counter */
	struct libtrace_stat_t *statistics = trace_get_statistics(trace, NULL);
	if(statistics->dropped > tally->lost_packets) {
		/* update lost packets to the new number of dropped packets */
		tally->lost_packets = statistics->dropped;
	}

	/* If the current timestamp is greater than the last printed plus the interval, output a result */
	if((key >> 32) >= (tally->lastkey >> 32) + tickrate) {

		/* update last key */
                tally->lastkey = key;

		/* Output the results with the key in epoch seconds*/
                output_results(tally, key >> 32);

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
			/* Clear all the stats data */
			tally->stats->mode_src[i] = 0;
                	tally->stats->mode_dst[i] = 0;
                	tally->stats->mean_src[i] = 0;
                	tally->stats->mean_dst[i] = 0;
                	tally->stats->median_src[i] = 0;
                	tally->stats->median_dst[i] = 0;
                	tally->stats->stddev_src[i] = 0;
                	tally->stats->stddev_dst[i] = 0;
                	tally->stats->variance_src[i] = 0;
        	        tally->stats->variance_dst[i] = 0;
       	        	tally->stats->skewness_src[i] = 0;
	                tally->stats->skewness_dst[i] = 0;
                }
		/* free the priority queue */
		for(i=0;i<4;i++) {
			free(tally->stats->rank_src[i]);
			free(tally->stats->rank_dst[i]);
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
		/* Then output the results */
		output_results(tally, (tally->lastkey >> 32) + 1);
	}
	/* Cleanup tally results*/
	free(tally);
}

static void libtrace_cleanup(libtrace_t *trace, libtrace_callback_set_t *processing,
	libtrace_callback_set_t *reporting, struct exclude_networks *exclude) {
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
	if(exclude->count > 0) {
		free(exclude->networks);
	}
	if(exclude) {
		free(exclude);
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

static void usage(char *argv0) {
	fprintf(stderr, "Usage:\n"
	"%s inputURI output-interval\n"
	"-i [inputURI] --set-uri [inputURI]\n"
	"-o [output-interval] --output-interval [output-interval]\n"
	"	Output statistical information every x seconds\n"
	"-t [threads] --threads [threads]\n"
	"-e [excluded-network] --exclude-network [excluded-network]\n"
	"	Network to exclude from results\n"
	"	e.g. -e 192.168.0.0/16 -e 10.0.0.0/8\n"
	"-d [output-directory] --output-dir [output-directory]\n"
	, argv0);
	exit(1);
}

int main(int argc, char *argv[]) {

	char *inputURI = NULL;
	int threads = 4;
	tickrate = 300;
	struct exclude_networks *exclude = malloc(sizeof(struct exclude_networks));
	exclude->count = 0;

	while(1) {
		int option_index = 0;
		struct option long_options[] = {
			{ "set-uri",		1, 0, 'i' },
			{ "output-interval",	1, 0, 'o' },
			{ "threads",		1, 0, 't' },
			{ "exclude-network",	1, 0, 'e' },
			{ "output-dir",		1, 0, 'd' },
			{ NULL,			0, 0,  0  }
		};

		int c = getopt_long(argc, argv, "i:o:t:e:d:", long_options, &option_index);

		if(c==-1) {
			break;
		}

		switch(c) {
			case 'i':
				inputURI = optarg;
				break;
			case 'o':
				tickrate = atoi(optarg);
				break;
			case 't':
				threads = atoi(optarg);
				break;
			case 'e':
				exclude->count += 1;
				if(exclude->count > 1) {
					exclude->networks = realloc(exclude->networks, sizeof(struct network)*exclude->count);
				} else {
					exclude->networks = malloc(sizeof(struct network));
				}
				if(get_network(optarg, &exclude->networks[exclude->count-1])) {
					fprintf(stderr, "Error excluding network %s\n", optarg);
                        		return 1;
				}
				break;
			case 'd':
				stats_outputdir = optarg;
				break;
			case '?':
				break;
			default:
				fprintf(stderr, "Unknown option: %c\n", c);
				usage(argv[0]);
		}
	}

	libtrace_t *trace;
	/* Callbacks for processing and reporting threads */
	libtrace_callback_set_t *processing, *reporter;

	/* Ensure the input URI was supplied */
        if(inputURI == NULL) {
                usage(argv[0]);
        }

	/* Create the trace */
        trace = trace_create(inputURI);
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
	trace_set_perpkt_threads(trace, threads);
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

	/* Start the trace, if it errors return */
	if(trace_pstart(trace, exclude, processing, reporter)) {
		trace_perror(trace, "Starting parallel trace");
		libtrace_cleanup(trace, processing, reporter, exclude);
		return 1;
	}

	/* This will wait for all threads to complete */
	trace_join(trace);

	/* Clean up everything */
	libtrace_cleanup(trace, processing, reporter, exclude);

	return 0;
}
