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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <getopt.h>

#include "libtrace.h"
#include "dagformat.h"
#include "utils.h"
#include "getdate.h"


struct libtrace_t *trace;
struct libtrace_filter_t *filter;

#define SCANSIZE 4096


static void     parse_cmdline(int argc, char **argv);
static void     usage();


static char     buffer[SCANSIZE];
static char     *inputuri = 0;
static char     *outputfilename = 0;
static char     *starttime = 0;
static char     *finishtime = 0;
static char	*filterstring = 0;
static char     *prog = 0;
static uint64_t count = 0;
static time_t   stv = 0;
static time_t   ftv = 0;
static FILE     *outfile = 0;

int main(int argc, char *argv[]) {

        int psize = 0;
        time_t ts = 0;
        uint64_t number = 0; 
	struct libtrace_packet_t packet;
        parse_cmdline(argc,argv);

        // set up times
        if (starttime) {
                stv = get_date(starttime,NULL);
		fprintf(stderr,"Start time: %lu\n",stv);
        }
        if (finishtime) {
                ftv = get_date(finishtime,NULL);
		fprintf(stderr,"End time: %lu\n",ftv);
        }

        // setup output files
        if (outputfilename == 0) {
                outfile = stdout;
        } else {
                if ((outfile = fopen(outputfilename,"ab")) == 0) {
                        perror("fopen");
                        exit(0);
                }
        }
        
	if (inputuri == 0) {
		usage();
		exit(0);
	}
        // set up input files
        if ((trace = trace_create(inputuri)) == 0) {
                exit(0);
        }

	if (filterstring) {
		filter = trace_bpf_setfilter(filterstring);
	}


        for (;;) {
                if ((psize = trace_read_packet(trace, &packet)) == -1) {
                        // terminate
                        break;
                }

	
		if (filter && !trace_bpf_filter(filter,&packet)) {
			continue;
		}
		
		ts = (time_t)trace_get_seconds(&packet); 

		if (count > 0) {
			number ++;
                        fwrite(buffer,psize,1,outfile);
			if (number > count)  {
				fprintf(stderr,"Maximum number of packets reached\n");
				break;
			}
			// carry on the loop
			continue;
		}
                if (stv == 0 || ts > stv) {
                        if (ftv == 0 || ts <= ftv) {
                                fwrite(buffer,psize,1,outfile);
                        }
                }
                if (ts > ftv && ftv != 0) {
			fprintf(stderr,"Packet timestamp (%lu) exceeds maximum time stamp (%lu)\n",ts,ftv);
                        break;
                }

        }
        trace_destroy(trace);
        return 0;
}

static void parse_cmdline(int argc, char **argv) {
        int opt;
        prog = strdup(argv[0]);
        while((opt = getopt(argc, argv, "hi:o:s:e:f:c:")) != EOF) {
                switch(opt) {
                        case 'h':
                                usage();
                                /* never returns */
                        case 'i':
                                inputuri = optarg;
                                break;
                        case 'o':
                                outputfilename = optarg;
                                break;
                        case 's':
                                starttime = optarg;
                                break;
                        case 'e':
                                finishtime = optarg;
                                break;
			case 'f':
				filterstring = optarg;
				break;
			case 'c':
				if (starttime || finishtime) {
					printf("Can't have start/end time and a packet count, ignoring count\n");
				} else {
					count = atoi(optarg);
				}
				break;
                        default:
                                usage();
                }
        }

}
static void usage() {
        printf("usage: %s [-h] [-i inputuri] [-o outputfilename] [[-s starttime] [-e endtime]]|[-c count] [-f filterstring]\n",prog);
        printf("\n");
        printf("-h\t\tshow this usage message.\n");
        printf("-i file\tinput filename\n");
        printf("-o file\toutput filename\n");
        printf("-s start\ttime to start output at\n");
        printf("-e end\ttime to stop output at\n");
	printf("-c count\tnumber of packets to output\n");
	printf("-f filter\tbpf filter to apply\n");
        printf("\n");
        printf(" This will read over a DAG trace file <inputfile>, and will output all records between <start> and <finish> times to a new DAG-format file, <outputfile>. The inputfile can be gzip-compressed, however the output wont be.\n If the input or output files are not specified, they will default to stdin and standard out, respectively. If the start and finish times are not specified, they will default to the start of the trace and the end of the trace, respectively.\n");
        printf(" The start and finish times are in the following format: \"YYYY/MM/DD HH:MM:SS\", and should be given in your local timezome (they are internally converted to UTC)\n");
        exit(0);
}

