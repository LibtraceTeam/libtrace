#include <libtrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <getopt.h>

void usage(char *argv0)
{
	fprintf(stderr,"Usage: %s [ -i | --set-interface ] outputuri traceuri...\n",argv0);
	fprintf(stderr,"\n");
	fprintf(stderr,"Merges traces together, with -i each trace gets it's own direction/interface,\n without traces keep whatever direction/interface they have set\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	
	struct libtrace_out_t *output;
	struct libtrace_t **input;
	struct libtrace_packet_t **packet;
	bool *live;
	bool set_interface=false;
	int i=0;

	while (1) {
		int option_index;
		struct option long_options[] = {
			{ "set-interface", 	0, 0, 'i' },
			{ NULL,			0, 0, 0 },
		};

		int c=getopt_long(argc, argv, "i:",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 'i': set_interface=true; break;
			default:
				fprintf(stderr,"unknown option: %c\n",c);
				usage(argv[0]);

		}

	}

	if (optind+2<argc)
		usage(argv[0]);

	output=trace_create_output(argv[optind]);
	if (!output) {
		fprintf(stderr,"Unable to open output file %s\n",argv[optind]);
		return 1;
	}

	input=calloc((argc-optind),sizeof(struct libtrace_t *));
	packet=calloc((argc-optind),sizeof(struct libtrace_packet_t *));
	live=calloc((argc-optind),sizeof(bool));
	for(i=0;i<argc-optind;++i) {
		struct libtrace_t *f;
		struct libtrace_packet_t *p;
		f=trace_create(argv[i+optind]);
		p=trace_create_packet();
		input[i]=f;
		packet[i]=p;
		if (!input[i]) {
			fprintf(stderr,"Could not read %s\n",argv[i+optind]);
			return 1;
		}
		trace_read_packet(f,p);
	}

	while(1) {
		uint64_t oldest_ts=0;
		int oldest=-1;
		for(i=0;i<argc-2;++i) {
			if (!live[i] && input[i]) {
				int ret=trace_read_packet(input[i],packet[i]);
				if (ret<0) {
					/* Error */
					perror(argv[i+2]);
					trace_destroy(input[i]);
					input[i]=NULL;
				}
				else if (ret==0) {
					/* EOF */
					trace_destroy(input[i]);
					input[i]=NULL;
				}
				else
					live[i]=true;
			}
			if (live[i] && 
				(oldest==-1 || 
				 oldest_ts<trace_get_erf_timestamp(packet[i]))) {
				oldest=i;
				oldest_ts=trace_get_erf_timestamp(packet[i]);
			}
		}
		/* We have run out of packets! */
		if (oldest==-1) {
			break;
		}

		if (set_interface)
			trace_set_direction(packet[oldest],oldest);
		trace_write_packet(output,packet[oldest]);
		live[oldest]=false;
		
	}
	trace_destroy_output(output);

	return 0;
}
