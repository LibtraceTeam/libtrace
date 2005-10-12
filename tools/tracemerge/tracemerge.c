#include <libtrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>

int main(int argc, char *argv[])
{
	
	struct libtrace_out_t *output;
	struct libtrace_t **input;
	struct libtrace_packet_t *packet;
	bool *live;
	int i=0;

	if (argc<2) {
		printf("Usage: %s outputuri traceuri...\n",argv[0]);
		printf("\n");
		printf("Merges traces together, each trace gets it's own direction\n");
		return 1;
	}

	output=trace_output_create(argv[1]);
	if (!output) {
		fprintf(stderr,"Unable to open output file %s\n",argv[1]);
		return 1;
	}

	input=calloc((argc-2),sizeof(struct libtrace_t *));
	packet=calloc((argc-2),sizeof(struct libtrace_packet_t));
	live=calloc((argc-2),sizeof(bool));
	for(i=0;i<argc-2;++i) {
		struct libtrace_t *f;
		struct libtrace_packet_t p;
		f=trace_create(argv[i+2]);
		input[i]=f;
		if (!input[i]) {
			fprintf(stderr,"Could not read %s\n",argv[i+2]);
			return 1;
		}
		else {
			fprintf(stderr,"Created %s @ %p\n",argv[i+2],input[i]);
		}
		trace_read_packet(f,&p);
	}

	while(1) {
		uint64_t oldest_ts=0;
		int oldest=-1;
		for(i=0;i<argc-2;++i) {
			if (!live[i] && input[i]) {
				int ret=trace_read_packet(input[i],&packet[i]);
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
				 oldest_ts<trace_get_erf_timestamp(&packet[i]))) {
				oldest=i;
				oldest_ts=trace_get_erf_timestamp(&packet[i]);
			}
		}
		/* We have run out of packets! */
		if (oldest==-1) {
			break;
		}

		trace_set_direction(&packet[oldest],oldest);
		trace_write_packet(output,&packet[oldest]);
		live[oldest]=false;
		
	}
	trace_output_destroy(output);

	return 0;
}
