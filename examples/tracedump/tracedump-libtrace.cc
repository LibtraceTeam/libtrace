#include <libtrace.h>
#include <err.h>
#include <time.h>
#include "tracedump.h"
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

void usage(char *argv0) 
{
	fprintf(stderr,"Usage:\n"
	"%s flags inputfile\n"
	"-f --filter=expr	BPF filter specification, quoted\n"
	"-c --count=num		terminate after num packets\n"
	,argv0);
	exit(0);
}

int main(int argc,char **argv)
{
	struct libtrace_t *trace = NULL;
	struct libtrace_packet_t packet;
	struct libtrace_filter_t *filter=NULL;
	uint64_t count=0;
	uint64_t numpackets=0;
	

	if (argc<2)
		usage(argv[0]);

	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",	1, 0, 'f' },
			{ "count",	1, 0, 'c' },
			{ NULL,		0, 0, 0 },
		};

		int c=getopt_long(argc,argv,"f:c:",
				long_options, &option_index);
		if (c == -1)
			break;
		switch(c) {
			case 'f': 
				if (filter!=NULL) {
					fprintf(stderr,"You can only have one filter (quote it with " ")\n");
					usage(argv[0]);
				}
				filter=trace_bpf_setfilter(optarg);
				break;
			case 'c': count=atol(optarg); break;
			default:
				  printf("unknown option: %c\n",c);
				  usage(argv[0]);
		}
	}
				
	

	while(optind <argc) {
		trace = trace_create(argv[optind]);
		numpackets = 0;
		if (!trace) {
			errx(1,"Failed to open trace");
		}

		while(trace_read_packet(trace,&packet)> 0 ){
			time_t sec = (time_t)trace_get_seconds(&packet);
			char *link=(char *)trace_get_link(&packet);
			if (filter && !trace_bpf_filter(filter,&packet))
				continue;

			printf("%s",ctime(&sec));
			per_packet(trace_get_link_type(&packet),
					link,
					packet.size-(link-packet.buffer));
			if(count) {
				numpackets++;
				if (numpackets == count)
					break;
			}
		}

		trace_destroy(trace);
		optind ++;
	}
	return 0;
}
