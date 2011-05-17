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
