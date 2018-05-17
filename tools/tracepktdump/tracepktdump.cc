/*
 *
 * Copyright (c) 2007-2016 The University of Waikato, Hamilton, New Zealand.
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


#include <libtrace.h>
#include <err.h>
#include <time.h>
#include "libpacketdump.h"
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

void usage(char *argv0) 
{
	fprintf(stderr,"Usage:\n"
	"%s flags inputfile\n"
	"-f --filter=expr	BPF filter specification, quoted\n"
	"-c --count=num		terminate after num packets\n"
	"-H --libtrace-help	Print libtrace runtime documentation\n"
		,argv0);
	exit(0);
}

int main(int argc,char **argv)
{
	struct libtrace_t *trace = NULL;
	struct libtrace_packet_t *packet = trace_create_packet();
	struct libtrace_filter_t *filter=NULL;
	uint64_t count=0;
	uint64_t numpackets=0;
	

	if (argc<2)
		usage(argv[0]);

	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",	   1, 0, 'f' },
			{ "count",	   1, 0, 'c' },
			{ "libtrace-help", 0, 0, 'H' },
			{ NULL,		   0, 0, 0   },
		};

		int c=getopt_long(argc,argv,"f:c:H",
				long_options, &option_index);
		if (c == -1)
			break;
		switch(c) {
			case 'f': 
				if (filter!=NULL) {
					fprintf(stderr,"You can only have one filter\n");
					usage(argv[0]);
				}
				filter=trace_create_filter(optarg);
				break;
			case 'c': count=atol(optarg); break;
			case 'H': 
				  trace_help(); 
				  exit(1);
				  break;
			default:
				  printf("unknown option: %c\n",c);
				  usage(argv[0]);
		}
	}
				
	

	while(optind <argc) {
		trace = trace_create(argv[optind]);
		optind ++;
		numpackets = 0;
		if (trace_is_err(trace)) {
			trace_perror(trace,"trace_create");
			trace_destroy(trace);
			continue;
		}

		trace_start(trace);
		if (trace_is_err(trace)) {
			trace_perror(trace,"trace_start");
			trace_destroy(trace);
			continue;
		}
		while(trace_read_packet(trace,packet)> 0 ){
			if (filter && !trace_apply_filter(filter,packet))
				continue;
			if (packet->type < TRACE_RT_DATA_SIMPLE)
				/* Ignore RT messages */
				continue;
                        if (trace_is_err(trace)) {
                                break;
                        }
			trace_dump_packet(packet);

			if(count) {
				numpackets++;
				if (numpackets == count)
					break;
			}
		}
		printf("\n");

		if (trace_is_err(trace)) {
			trace_perror(trace, "trace_read_packet");
		}
		trace_destroy(trace);
	}
	return 0;
}
