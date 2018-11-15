#include "libtrace_parallel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>

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
	uint64_t output_count;
	/* Pointer to stats structure */
	struct addr_stats *stats;
};
struct addr_stats {
	/* Holds the percentage change compared to the previous output */
	float src[4][256];
	float dst[4][256];
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

/* interval between outputs in seconds */
uint64_t tickrate;

char *stats_outputdir = "/home/jcv9/output-spectre/";
/* Calculate and plot the percentage change from the previous plot */
int stats_percentage_change = 0;

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

	/* Calculates the percentage change from the last output. NEED TO MAKE THIS WEIGHTED */
        if(stats_percentage_change) {
		for(i=0;i<256;i++) {
        		for(j=0;j<4;j++) {
                		tally->stats->src[j][i] = 0;
                        	tally->stats->dst[j][i] = 0;
                        	if(tally->src[j][i] != 0) {
                        		tally->stats->src[j][i] = (((float)tally->src[j][i] - (float)tally->src_lastoutput[j][i]) / (float)tally->src[j][i]) * 100;
                        	}
                        	if(tally->dst[j][i] != 0) {
                        		tally->stats->dst[j][i] = (((float)tally->dst[j][i] - (float)tally->dst_lastoutput[j][i]) / (float)tally->dst[j][i]) * 100;
                        	}
			}
                }
        }

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

		tally->stats->mean_src[k] = (k + (ex / n));
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
		tally->stats->mean_dst[k] = (k + (ex / n));
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
	tally->lastkey = 0;
	tally->packets = 0;
	tally->output_count = 0;

        return tally;
}

static void plot_results(struct addr_local *tally, uint64_t tick) {

	int i, j, k;

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
	printf("Generating output \"%sipdist-%lu\"\n", stats_outputdir, tick);

	/* Output the results */
	char outputfile[255];
	snprintf(outputfile, sizeof(outputfile), "%sipdist-%lu.data", stats_outputdir, tick);
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
	snprintf(outputfile_stats, sizeof(outputfile_stats), "%sipdist-%lu.stats", stats_outputdir, tick);
	tmp = fopen(outputfile_stats, "w");
	/* append stats data to end of file */
	fprintf(tmp, "#\tmean\tstddev\tvariance\tmedian\tmode\tskewness\n");
	for(i=0;i<4;i++) {
		fprintf(tmp, "src%d\t%0.f\t%0.f\t%0.f\t\t%0.f\t%0.f\t%f\n", i+1, tally->stats->mean_src[i], tally->stats->stddev_src[i], tally->stats->variance_src[i], tally->stats->median_src[i], tally->stats->mode_src[i], tally->stats->skewness_src[i]);
		fprintf(tmp, "dst%d\t%0.f\t%0.f\t%0.f\t\t%0.f\t%0.f\t%f\n", i+1, tally->stats->mean_dst[i], tally->stats->stddev_dst[i], tally->stats->variance_dst[i], tally->stats->median_src[i], tally->stats->mode_dst[i], tally->stats->skewness_dst[i]);
		fprintf(tmp, "\n\n");
	}
        fclose(tmp);

	/* Puts data into timeseries files that gnuplot likes */
	char outputfile2[255];
	for(k=0;k<2;k++) {
		for(j=0;j<4;j++) {
			/* If k is 0 we are doing src else dst */
			if(k) {
				snprintf(outputfile2, sizeof(outputfile2), "%sipdist-timeseries-dst-octet%d.data", stats_outputdir, j+1);
			} else {
				snprintf(outputfile2, sizeof(outputfile2), "%sipdist-timeseries-src-octet%d.data", stats_outputdir, j+1);
			}
			if(tally->output_count == 0) {
				tmp = fopen(outputfile2, "w");
				fprintf(tmp, "timestamp\t");
				for(i=0;i<256;i++) {
					fprintf(tmp, "%d\t", i);
				}
				fprintf(tmp, "\n");
			} else {
				tmp = fopen(outputfile2, "a");
			}
			fprintf(tmp, "%lu\t", tick);
			for(i=0;i<256;i++) {
				if(k) {
					fprintf(tmp, "%lu\t", tally->dst[j][i]);
				} else {
					fprintf(tmp, "%lu\t", tally->src[j][i]);
				}
			}
			fprintf(tmp, "\n");
			fclose(tmp);
        	}
	}


	/* Get the version of gnuplot */
	//char delim[] = " ";
	//char gnuplot_result[256];
	//double gnuplot_version = 0;
	//FILE *gnuplot = popen("gnuplot --version", "r");
	//fgets(gnuplot_result, sizeof(gnuplot_result)-1, gnuplot);
	//strtok(gnuplot_result, delim);
	//gnuplot_version = atof(strtok(NULL, delim));
	//pclose(gnuplot);

	/* Plot the results */
	for(i=0;i<4;i++) {
		char outputplot[255];
		snprintf(outputplot, sizeof(outputplot), "%sipdist-%lu-octet%d.png", stats_outputdir, tick, i+1);
       		/* Open pipe to gnuplot */
		FILE *gnuplot = popen("gnuplot -persistent", "w");
        	/* send all commands to gnuplot */
        	fprintf(gnuplot, "set term pngcairo enhanced size 1280,960\n");
		fprintf(gnuplot, "set output '%s'\n", outputplot);
		fprintf(gnuplot, "set multiplot layout 2,1\n");
		fprintf(gnuplot, "set title 'IP Distribution'\n");
		fprintf(gnuplot, "set xrange[0:255]\n");
		fprintf(gnuplot, "set xlabel 'Prefix'\n");
		fprintf(gnuplot, "set ylabel 'Hits'\n");
		fprintf(gnuplot, "set xtics 0,10,255\n");
		/* Setup labels that hold mean, standard deviation and variance */
		fprintf(gnuplot, "stats '%s' index %d every ::0::0 using 2 name 'SOURCEMEAN' nooutput\n", outputfile_stats, i);
		//fprintf(gnuplot, "set label 1 gprintf(\"Source Mean %u\", SOURCEMEAN_min) at graph 0.02, 0.95\n");
		fprintf(gnuplot, "stats '%s' index %d every ::1::1 using 2 name 'DESTMEAN' nooutput\n", outputfile_stats, i);
                //fprintf(gnuplot, "set label 2 gprintf(\"Destination Mean: %f\", DESTMEAN_min) at graph 0.02, 0.90\n");
		//fprintf(gnuplot, "stats '%s' index %d every ::0::0 using 3 name 'SOURCESTDDEV' nooutput\n", outputfile_stats, i);
                //fprintf(gnuplot, "set label 3 sprintf('Source Standard Deviation: %f', SOURCESTDDEV_min) at graph 0.24, 0.95\n");
                //fprintf(gnuplot, "stats '%s' index %d every ::1::1 using 3 name 'DESTSTDDEV' nooutput\n", outputfile_stats, i);
                //fprintf(gnuplot, "set label 4 sprintf('Destination Standard Deviation: %f', DESTSTDDEV_min) at graph 0.24, 0.90\n");
		//fprintf(gnuplot, "stats '%s' index %d every ::0::0 using 4 name 'SOURCEVAR' nooutput\n", outputfile_stats, i);
                //fprintf(gnuplot, "set label 5 sprintf('Source Variance: %f', SOURCEVAR_min) at graph 0.55, 0.95\n");
                //fprintf(gnuplot, "stats '%s' index %d every ::1::1 using 4 name 'DESTVAR' nooutput\n", outputfile_stats, i);
                //fprintf(gnuplot, "set label 6 sprintf('Destination Variance: %f', DESTVAR_min) at graph 0.55, 0.90\n");
		/* Plot the first graph of the multiplot */
		fprintf(gnuplot, "set arrow from SOURCEMEAN_min, graph 0 to SOURCEMEAN_min, graph 1 nohead lt 1\n");
		fprintf(gnuplot, "set arrow from DESTMEAN_min, graph 0 to DESTMEAN_min, graph 1 nohead lt 2\n");
		fprintf(gnuplot, "plot '%s' using %d:%d index 0 title 'Source octet %d' smooth unique with boxes,", outputfile, (i*4)+3,(i*4)+4, i+1);
		fprintf(gnuplot, "'%s' using %d:%d index 0 title 'Destination octet %d' smooth unique with boxes,", outputfile, (i*4)+5, (i*4)+6, i+1);
		fprintf(gnuplot, "1/0 t 'Source mean' lt 1,");
		fprintf(gnuplot, "1/0 t 'Destination mean' lt 2\n");
		/* Unset labels for next plot */
		fprintf(gnuplot, "unset arrow\n");
		fprintf(gnuplot, "unset label 1\nunset label 2\nunset label 3\nunset label 4\nunset label 5\nunset label 6\n");
		fprintf(gnuplot, "set title 'Zipf Distribution'\n");
		fprintf(gnuplot, "set xlabel 'Rank'\n");
		fprintf(gnuplot, "set ylabel 'Frequency'\n");
		fprintf(gnuplot, "set logscale xy 10\n");
		fprintf(gnuplot, "set xrange[1:255]\n");
		fprintf(gnuplot, "set xtics 0,10,255\n");
		/* Plot the second graph of the multiplot */
		fprintf(gnuplot, "plot '%s' using 2:%d index 0 title 'Source octet %d',", outputfile, (i*4)+4, i+1);
		fprintf(gnuplot, "'%s' using 2:%d index 0 title 'Destination octet %d'\n", outputfile, (i*4)+6, i+1);
		fprintf(gnuplot, "unset multiplot\n");
        	pclose(gnuplot);
	}

	/* Plot time series */
	for(k=0;k<2;k++) {
		for(i=0;i<4;i++) {
			char outputplot2[255];
			if(k) {
				snprintf(outputplot2, sizeof(outputplot2), "%sipdist-timeseries-dst-octet%i.png", stats_outputdir, i+1);
			} else {
				snprintf(outputplot2, sizeof(outputplot2), "%sipdist-timeseries-src-octet%i.png", stats_outputdir, i+1);
			}
			FILE *gnuplot = popen("gnuplot -persistent", "w");
			fprintf(gnuplot, "set term pngcairo size 1280,960 \n");
			fprintf(gnuplot, "set output '%s'\n", outputplot2);
			if(k) {
				fprintf(gnuplot, "set title 'Timeseries Dst Octet %i - Cumulative'\n", i+1);
			} else {
				fprintf(gnuplot, "set title 'Timeseries Src Octet %i - Cumulative'\n", i+1);
			}
			fprintf(gnuplot, "set xtics rotate\n");
			//fprintf(gnuplot, "set key out vert\n");
			fprintf(gnuplot, "set key off\n");
			//fprintf(gnuplot, "set xdata time\n");
			//fprintf(gnuplot, "set timefmt '%%s'\n");
			//fprintf(gnuplot, "set format x '%%m/%%d/%%Y %%H:%%M:%%S'\n");
			fprintf(gnuplot, "set autoscale xy\n");
			if(k) {
				//if(gnuplot_version < 5) {
					fprintf(gnuplot, "plot '%sipdist-timeseries-dst-octet%d.data' using 2:xtic(1) with lines title columnheader(2) smooth cumulative, for[i=3:257] '' using i with lines title columnheader(i) smooth cumulative\n", stats_outputdir, i+1);
				//} else {
				//	fprintf(gnuplot, "plot '%sipdist-timeseries-dst-octet%d.data' using 2:xtic(1) with lines title columnheader(2) at end smooth cumulative, for[i=3:257] '' using i with lines title columnheader(i) at end smooth cumulative\n", stats_outputdir, i+1);
				//}
			} else {
				//if(gnuplot_version < 5) {
					fprintf(gnuplot, "plot '%sipdist-timeseries-src-octet%d.data' using 2:xtic(1) with lines title columnheader(2) smooth cumulative, for[i=3:257] '' using i with lines title columnheader(i) smooth cumulative\n", stats_outputdir, i+1);
				//} else {
				//	fprintf(gnuplot, "plot '%sipdist-timeseries-src-octet%d.data' using 2:xtic(1) with lines title columnheader(2) at end smooth cumulative, for[i=3:257] '' using i with lines title columnheader(i) at end smooth cumulative\n", stats_outputdir, i+1);
				//}
			}
			fprintf(gnuplot, "replot");
			pclose(gnuplot);
		}
	}
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
		/* Then plot the results */
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
