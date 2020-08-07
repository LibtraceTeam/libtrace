/*
 *
 * Copyright (c) 2007-2020 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */


/* Tool that compares two traces and outputs any packets that do not match
 * between the two
 *
 * Author: Jacob van Walraven
 */

#include "libtrace.h"
#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>

#include "libpacketdump.h"

uint32_t max_diff = 0;
uint32_t dumped_diff = 0;

struct packet_window {
    /* -1 = trace error
     *  0 = EOF
     *  1 = INT_MAX packet processed
     */
    int status;
    uint32_t hash;
    libtrace_packet_t *packet;
};

void fill_packet_windows(libtrace_t *trace_a, libtrace_t *trace_b,
                         struct packet_window *a, int a_pos,
                         struct packet_window *b, int b_pos,
                         int window_size);

static uint32_t hash_packet(libtrace_packet_t *packet) {

    libtrace_linktype_t ltype;
    uint32_t rem, i;

    const char *str = (const char *)trace_get_packet_buffer(packet, &ltype, &rem);
    if (!str)
        return 0;

    /* djb hashing algorithm */
    unsigned long hash = 5381;
    for (i = 0; i < rem; str++, i++) {
        hash = ((hash << 5) + hash) + (*str);
    }

    return hash;
}

/* Compares the two provided packets. If the packets differ in any fashion,
 * both will be dumped to standard output using libpacketdump followed by a
 * line of asterisks.
 *
 * Note that only the contents of the packet are compared; the framing provided
 * by the trace format, e.g. the ERF or PCAP header, is not examined.
 */
static int compare_packets(struct packet_window *a, struct packet_window *b) {

	char *buf_a, *buf_b;
	libtrace_linktype_t lt;
	uint32_t rem_a, rem_b;

        /* if the hash doesnt match the rest of the packet wont */
        if (a->hash != b->hash) {
            return 0;
        }

	buf_a = trace_get_packet_buffer(a->packet, &lt, &rem_a);
	buf_b = trace_get_packet_buffer(b->packet, &lt, &rem_b);

	if (rem_a > trace_get_wire_length(a->packet))
		rem_a = trace_get_wire_length(a->packet);

	if (rem_b > trace_get_wire_length(b->packet))
		rem_b = trace_get_wire_length(b->packet);


	if (!buf_a && !buf_b)
		return 1;

	if (!buf_a || !buf_b) {
		return 0;
	}


	if (rem_a == 0 || rem_b == 0)
		return 1;

	if (rem_a != rem_b) {
		return 0;
	}

	/* This is not exactly going to be snappy, but it's the easiest way
	 * to look for differences */
	if (memcmp(buf_a, buf_b, rem_a) != 0) {
                return 0;
	}

        return 1;

}

static void dump_packet(libtrace_out_t *output, libtrace_packet_t *packet) {

    if (packet == NULL) {
        return;
    }

    if (output != NULL) {
        trace_write_packet(output, packet);
    } else {
        trace_dump_packet(packet);
    }

}

static void usage(char *prog) {
	printf("Usage instructions for %s\n\n", prog);
	printf("\t%s [options] traceA traceB\n\n", prog);
	printf("Supported options:\n");
	printf("\t-m <max>   Stop after <max> differences have been reported\n");
	printf("\t-w <window> The size of the window to match packets with\n");
        printf("\t-a <traceA-diff.pcap> Write traceA differences to file\n");
        printf("\t-b <traceB-diff.pcap> Write traceB differences to file\n");
	return;

}

void fill_packet_windows(libtrace_t *trace_a, libtrace_t *trace_b,
                         struct packet_window *a, int a_pos,
                         struct packet_window *b, int b_pos,
                         int window_size) {
    int pos, i;

    /* Window A */
    for (i = a_pos; i < a_pos + window_size; i++) {

        pos = i % window_size;

        if (a[pos].status == INT_MAX) {
            a[pos].status =
                trace_read_packet(trace_a, a[pos].packet);
            if (a[pos].status > 0) {
                a[pos].hash = hash_packet(a[pos].packet);
            } else {
                a[pos].hash = 0;
            }
        }
    }

    /* Window B */
    for (i = b_pos; i < b_pos + window_size; i++) {

        pos = i % window_size;

        if (b[pos].status == INT_MAX) {
            b[pos].status =
                trace_read_packet(trace_b, b[pos].packet);
            if (b[pos].status > 0) {
                b[pos].hash = hash_packet(b[i % window_size].packet);
            } else {
                b[pos].hash = 0;
            }
        }
    }

}

int main(int argc, char *argv[])
{

        struct packet_window *packet_window[2];
        int window_size = 20, i;
        uint64_t w_pos[2], j;
        uint64_t b_pos[2];
        char *output_file[2] = {NULL, NULL};
        libtrace_out_t *output[2] = {NULL, NULL};
	libtrace_t *trace[2];
        bool match;

	if (argc<2) {
		usage(argv[0]);
		return -1;
	}


	while (1) {
		int option_index;
		struct option long_options[] = {
			{ "max",	 1, 0, 'm' },
			{ "window",      1, 0, 'w' },
                        { "traceA-diff", 1, 0, 'a' },
                        { "traceB-diff", 1, 0, 'b' },
			{ "help",        0, 0, 'h' },
		};

		int c = getopt_long(argc, argv, "m:w:a:b:h", long_options, &option_index);

                if (c == -1)
			break;

		switch (c) {
			case 'm':
				if (atoi(optarg) < 0) {
					fprintf(stderr, "-m option must not be negative - ignoring\n");
				} else {
					max_diff = (uint32_t) atoi(optarg);
				}
				break;
			case 'w':
                                window_size=atoi(optarg);
                                break;
                        case 'a':
                                output_file[0] = optarg;
                                break;
                        case 'b':
                                output_file[1] = optarg;
                                break;
                        case 'h':
                                usage(argv[0]);
                                return 0;
			default:
				fprintf(stderr, "Unknown option: %c\n", c);
				usage(argv[0]);
				return 1;
		}
	}

        /* setup packet window */
        packet_window[0] = malloc(sizeof(struct packet_window) * window_size);
        packet_window[1] = malloc(sizeof(struct packet_window) * window_size);
        if (packet_window[0] == NULL || packet_window[1] == NULL) {
            fprintf(stderr, "Unable to allocate memory, try reducing window size\n");
            return 1;
        }
        w_pos[0] = 0;
        w_pos[1] = 0;
        b_pos[0] = 0;
        b_pos[1] = 0;

        /* create each packet */
        for (i = 0; i < window_size; i++) {
            packet_window[0][i].packet = trace_create_packet();
            packet_window[1][i].packet = trace_create_packet();
            if (packet_window[0][i].packet == NULL
                || packet_window[0][i].packet == NULL) {

                fprintf(stderr, "Unable to allocate memory, try reducing window size\n");
                return 1;
            }
            packet_window[0][i].status = INT_MAX;
            packet_window[1][i].status = INT_MAX;
        }

        /* create and start trace A */
	trace[0] = trace_create(argv[optind++]);
	if (trace_is_err(trace[0])) {
		trace_perror(trace[0],"Opening trace file");
		return -1;
	}
	if (trace_start(trace[0])) {
		trace_perror(trace[0],"Starting trace");
		trace_destroy(trace[0]);
		return -1;
	}

        /* create and start trace B */
	trace[1] = trace_create(argv[optind++]);
	if (trace_is_err(trace[1])) {
		trace_perror(trace[1],"Opening trace file");
		return -1;
	}
	if (trace_start(trace[1])) {
		trace_perror(trace[1],"Starting trace");
		trace_destroy(trace[1]);
		return -1;
	}

        /* if we are outputting to file create output trace */
        if (output_file[0] != NULL) {
            output[0] = trace_create_output(output_file[0]);
            if (trace_is_err_output(output[0])) {
                trace_perror_output(output[0], "Creating trace file");
                return -1;
            }
            if (trace_start_output(output[0])) {
                trace_perror_output(output[0], "Starting trace");
                trace_destroy_output(output[0]);
                return -1;
            }
        }
        if (output_file[1] != NULL) {
            output[1] = trace_create_output(output_file[1]);
            if (trace_is_err_output(output[1])) {
                trace_perror_output(output[1], "Creating trace file");
                return -1;
            }
            if (trace_start_output(output[1])) {
                trace_perror_output(output[1], "Starting trace");
                trace_destroy_output(output[1]);
                return -1;
            }
        }

        /* prime the packet window */
        fill_packet_windows(trace[0], trace[1],
                            packet_window[0], w_pos[0],
                            packet_window[1], w_pos[1],
                            window_size);

        /* loop while we still have packets in both windows */
        while (packet_window[0][w_pos[0] % window_size].status > 0 && packet_window[1][w_pos[1] % window_size].status > 0) {

            /* If packets do not match */
            if (!compare_packets(&packet_window[0][w_pos[0] % window_size],
                                 &packet_window[1][w_pos[1] % window_size])) {

               /* record position of window B */
               b_pos[1] = w_pos[1];
               /* advance window B */
               w_pos[1] += 1;

               /* advance window B until a packet match is found or we reach the end of the window */
               while (!(match = compare_packets(&packet_window[0][w_pos[0] % window_size],
                                                &packet_window[1][w_pos[1] % window_size]))
                      && w_pos[1] < b_pos[1] + window_size) {

                   w_pos[1] += 1;
               }

               /* if a match was found */
               if (match) {

                   /* output all packets prior to the matched packed on window B */
                   for (j = b_pos[1]; j < w_pos[1]; j++) {

                       dump_packet(output[1], packet_window[1][j % window_size].packet);
                       packet_window[1][j % window_size].status = INT_MAX;
                       if (++dumped_diff >= max_diff && max_diff > 0)
                           goto end;
                   }

                   /* refil the packet windows */
                   fill_packet_windows(trace[0], trace[1], packet_window[0], w_pos[0],
                                       packet_window[1], w_pos[1], window_size);

               /* if a match was not found */
               } else {

                   w_pos[1] = b_pos[1];
                   b_pos[0] = w_pos[0];
                   w_pos[0] += 1;

                   /* advance window A until a packet match is found or we reach the end of window A */
                   while (!(match = compare_packets(&packet_window[0][w_pos[0] % window_size],
                                                    &packet_window[1][w_pos[1] % window_size]))
                          && w_pos[0] < b_pos[0] + window_size) {

                       w_pos[0] += 1;
                   }

                   /* if a match was found */
                   if (match) {

                       /* output all window A packets prior to the match */
                       for (j = b_pos[0]; j < w_pos[0]; j++) {

                           dump_packet(output[0], packet_window[0][j % window_size].packet);
                           packet_window[0][j % window_size].status = INT_MAX;
                           if (++dumped_diff >= max_diff && max_diff > 0)
                               goto end;
                       }

                       /* refil the packet window */
                       fill_packet_windows(trace[0], trace[1], packet_window[0], w_pos[0],
                                           packet_window[1], w_pos[1], window_size);

                   /* if a match was not found */
                   } else {
                       /* output the current window A packet and mark packet complete */
                       dump_packet(output[0], packet_window[0][b_pos[0] % window_size].packet);
                       packet_window[0][b_pos[0] % window_size].status = INT_MAX;

                       /* output the current window B packet and mark packet complete */
                       dump_packet(output[1], packet_window[1][b_pos[1] % window_size].packet);
                       packet_window[1][b_pos[1] % window_size].status = INT_MAX;

                       /* refil the packet window */
                       fill_packet_windows(trace[0], trace[1], packet_window[0], w_pos[0],
                                           packet_window[1], w_pos[1], window_size);

                       /* check max diff */
                       if (++dumped_diff >= max_diff && max_diff > 0)
                           goto end;

                       /* advance window A and window B */
                       w_pos[0] += 1;
                       w_pos[1] += 1;
                   }

               }

            /* packets are the same advance window A and window B */
            } else {

                /* mark active packet in window A and B as complete */
                packet_window[0][w_pos[0] % window_size].status = INT_MAX;
                packet_window[1][w_pos[1] % window_size].status = INT_MAX;
                /* refill packet windows */
                fill_packet_windows(trace[0], trace[1],
                            packet_window[0], w_pos[0],
                            packet_window[1], w_pos[1],
                            window_size);
                /* advance window A and window B */
                w_pos[0] += 1;
                w_pos[1] += 1;
            }

        }

        /* if either trace has any remamining packets dump them */
        while (packet_window[0][w_pos[0] % window_size].status > 0) {

            dump_packet(output[0], packet_window[0][w_pos[0] % window_size].packet);
            packet_window[0][w_pos[0] % window_size].status = INT_MAX;
            fill_packet_windows(trace[0], trace[1],
                                packet_window[0], w_pos[0],
                                packet_window[1], w_pos[1],
                                window_size);

            /* check max diff */
            if (++dumped_diff >= max_diff && max_diff > 0)
                goto end;

            w_pos[0] += 1;

        }

        while (packet_window[1][w_pos[1] % window_size].status > 0) {

            dump_packet(output[1], packet_window[1][w_pos[1] % window_size].packet);
            packet_window[1][w_pos[1] % window_size].status = INT_MAX;
            fill_packet_windows(trace[0], trace[1],
                                packet_window[0], w_pos[0],
                                packet_window[1], w_pos[1],
                                window_size);

            /* check max diff */
            if (++dumped_diff >= max_diff && max_diff > 0)
                goto end;

            w_pos[1] += 1;

        }
end:

        /* check for errors */
	if (trace_is_err(trace[0])) {
		trace_perror(trace[0],"Reading packets");
		trace_destroy(trace[0]);
		return -1;
	}
	if (trace_is_err(trace[1])) {
		trace_perror(trace[1],"Reading packets");
		trace_destroy(trace[1]);
		return -1;
	}

        /* destroy each packet */
        for (i = 0; i < window_size; i++) {
            trace_destroy_packet(packet_window[0][i].packet);
            trace_destroy_packet(packet_window[1][i].packet);
        }

        if (output[0] != NULL) {
            trace_destroy_output(output[0]);
        }
        if (output[1] != NULL) {
            trace_destroy_output(output[1]);
        }

        /* destroy traces */
        trace_destroy(trace[0]);
        trace_destroy(trace[1]);

        /* destroy each window */
        free(packet_window[0]);
        free(packet_window[1]);
}

/*
Packet windows
 A    B
[ ]  [ ]
[ ]  [ ]
[ ]  [ ]
[ ]  [ ]
[ ]  [ ]

Fill packet windows

while( window A && window B have packets ) {

    compare window A packet with window B packet
    if packets do not match
        record position of window B
        advance window B
        while (window A != window B && window B != end)
            advance window B
        if (window A == window B)
            output all packets from recorded window B position to current window B position
            refill the packet window
            continue
        else if (window B == end)
            reset window B position to the recorded window B position
            record window A position
            advance window A
            while (window A != Window B && window A != end)
                advance window A
            if (window A == window B)
                output all packets from recorded window A positon to the current window A position
                refill packet window A
                continue
            else if ( window A == end)
                output current window A and window B packets
                refill both windows
                advance window A and window B
                continue

    if packets match
        advance window A and window B
        refil the packet window
}
*/
