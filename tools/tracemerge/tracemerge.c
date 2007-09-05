#include <libtrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <getopt.h>
#include <signal.h>

static void usage(char *argv0)
{
	fprintf(stderr,"Usage:\n"
	"%s flags outputuri traceuri [traceuri...]\n"
	"-i [interfaces_per_input] --set-interface [interfaces_per_input]\n"
	"			Each trace is allocated an interface. Default leaves this flag as read from the original traces, if appropriate\n"
	"-u --unique-packets    Discard duplicate packets\n"
	"-H --libtrace-help     Print libtrace runtime documentation\n"
	,argv0);
	exit(1);
}

volatile int done=0;

static void cleanup_signal(int sig)
{
	done=1;
}

int main(int argc, char *argv[])
{
	
	struct libtrace_out_t *output;
	struct libtrace_t **input;
	struct libtrace_packet_t **packet;
	bool *live;
	int interfaces_per_input=0;
	bool unique_packets=false;
	int i=0;
	uint64_t last_ts=0;
	struct sigaction sigact;

	while (1) {
		int option_index;
		struct option long_options[] = {
			{ "set-interface", 	2, 0, 'i' },
			{ "unique-packets",	0, 0, 'u' },
			{ "libtrace-help",	0, 0, 'H' },
			{ NULL,			0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "i::uH",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 'i': 
				if (optarg) 
					interfaces_per_input=atoi(optarg);
				else
					interfaces_per_input=1;
				break;
			case 'u': unique_packets=true; break;
			case 'H': 
				  trace_help();
				  exit(1);
				  break;
			default:
				fprintf(stderr,"unknown option: %c\n",c);
				usage(argv[0]);

		}

	}

	if (optind+2>argc)
		usage(argv[0]);

	output=trace_create_output(argv[optind++]);
	if (trace_is_err_output(output)) {
		trace_perror_output(output,"trace_create_output");
		return 1;
	}
	if (trace_start_output(output)==-1) {
		trace_perror_output(output,"trace_start_output");
		return 1;
	}

	sigact.sa_handler = cleanup_signal;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = SA_RESTART;

	sigaction(SIGINT,&sigact,NULL);
	sigaction(SIGTERM,&sigact,NULL);

	input=calloc((size_t)(argc-optind),sizeof(struct libtrace_t *));
	packet=calloc((size_t)(argc-optind),sizeof(struct libtrace_packet_t *));
	live=calloc((size_t)(argc-optind),sizeof(bool));
	for(i=0;i<argc-optind;++i) {
		libtrace_t *f;
		libtrace_packet_t *p;
		f=trace_create(argv[i+optind]);
		if (trace_is_err(f)) {
			trace_perror(f,"trace_create");
			return 1;
		}
		if (trace_start(f)==-1) {
			trace_perror(f,"trace_start");
			return 1;
		}
		p=trace_create_packet();
		input[i]=f;
		packet[i]=p;
		if (trace_read_packet(f,packet[i])>0)
			live[i]=true;
	}

	while(1) {
		uint64_t oldest_ts=0;
		int oldest=-1;
		int curr_dir;
		if (done)
			break;
		for(i=0;i<argc-optind;++i) {
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
				 oldest_ts>trace_get_erf_timestamp(packet[i]))) {
				oldest=i;
				oldest_ts=trace_get_erf_timestamp(packet[i]);
			}
		}
		/* We have run out of packets! */
		if (oldest==-1) {
			break;
		}

		live[oldest]=false;

		curr_dir = trace_get_direction(packet[oldest]);
		if (curr_dir != -1 && interfaces_per_input) {
			/* If there are more interfaces than
			 * interfaces_per_input, then clamp at the 
			 * highest input.  This means things should
			 * end up in "OTHER" or the unused 3rd bin if
			 * we're lucky */
			curr_dir = curr_dir < interfaces_per_input
				? curr_dir
				: interfaces_per_input-1;

			trace_set_direction(packet[oldest],
					oldest*interfaces_per_input
					+curr_dir);
		}

		if (unique_packets && oldest_ts == last_ts)
			continue;

		if (trace_write_packet(output,packet[oldest]) < 0) {
			trace_perror_output(output, "trace_write_packet");
			break;
		}

		last_ts=oldest_ts;
		
	}
	trace_destroy_output(output);

	return 0;
}
