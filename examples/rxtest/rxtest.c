/*
 * This file is part of libtrace
 *
 * Copyright (c) 2004 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson 
 *          Perry Lorier 
 *          
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libtrace; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 *
 */

#include <stdio.h> /* printf */
#include <netinet/in.h> /* ntohs */
#include <netdb.h>
#include "dagformat.h"
#include <getopt.h>

#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include "libtrace.h"

struct libtrace_t *trace;

char *uri = 0;

uint64_t rxerr = 0;
uint64_t total = 0;
static void usage();
static void parse_cmdline(int argc, char **argv);

int main(int argc, char **argv) {

	struct libtrace_packet_t *packet = trace_create_packet();
	dag_record_t *erfptr;
	
        int psize;

	parse_cmdline(argc,argv);

	if (!uri) {
		printf("Incorrect usage: need a URI\n");
		usage(argv[0]);
	}
	trace = trace_create(uri);
	for (;;) {
		if ((psize = trace_read_packet(trace, &packet)) <= 0) {
			// terminate
			break;
		}

		erfptr = (dag_record_t *)packet.buffer;


		if (erfptr->flags.rxerror) {
			rxerr++;
			printf(".");
			fflush(stdout);
		}
		total++;

	}
	printf("RX Errors seen: %llu\n",(unsigned long long) rxerr);
	printf("Total packets seen: %llu\n",(unsigned long long)total);
	trace_destroy(trace);
        return 0;
}


static void usage(char *prog) {
	printf("usage: %s [-h] [-u <uri>] \n",prog);
	printf("        -h		this help message\n");
	printf("        -u uri		uri to connect to\n");
	printf("\n");
}

static void parse_cmdline(int argc, char **argv){
	int opt;
	if (argc == 1) {
		usage(argv[0]);
		exit(0);
	}
	
	while ((opt = getopt(argc,argv, "hu:")) != EOF) {
		switch(opt) {
			case 'h':
				usage(argv[0]);
				exit(0);
			case 'u':
				uri = strdup(optarg);
				break;
			default:
				usage(argv[0]);
				exit(0);
		}

	}

}
