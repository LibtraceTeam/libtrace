#include <libtrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>

static void usage(char *argv0)
{
	fprintf(stderr,"Usage:\n"
	"%s flags outputuri traceuri [traceuri...]\n"
	"-i [interfaces_per_input] --set-interface [interfaces_per_input]\n"
	"			Each trace is allocated an interface. Default leaves this flag as\n"
	"			read from the original traces, if appropriate\n"
	"-u --unique-packets    Discard duplicate packets\n"
	"-z level --compress-level level\n"
	"			Compression level\n"
	"-Z method --compress-type method\n"
	"			Compression method\n"
	"-H --libtrace-help     Print libtrace runtime documentation\n"
	,argv0);
	exit(1);
}

volatile int done=0;

static void cleanup_signal(int sig UNUSED)
{
	done=1;
	trace_interrupt();
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
	int compression=-1;
	char *compress_type_str = NULL;
	trace_option_compresstype_t compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;

	while (1) {
		int option_index;
		struct option long_options[] = {
			{ "set-interface", 	2, 0, 'i' },
			{ "unique-packets",	0, 0, 'u' },
			{ "libtrace-help",	0, 0, 'H' },
			{ "compress-level",	1, 0, 'z' },
			{ "compress-type", 	1, 0, 'Z' },
			{ NULL,			0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "i::uHz:Z:",
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
			case 'z':
				compression = atoi(optarg);
				if (compression<0 || compression>9) {
					fprintf(stderr,"Compression level must be between 0 and 9\n");
					usage(argv[0]);
				}
				break;

			case 'Z':
				compress_type_str = optarg;
				break;
			default:
				fprintf(stderr,"unknown option: %c\n",c);
				usage(argv[0]);

		}

	}

	if (optind+2>argc)
		usage(argv[0]);

	if (compress_type_str == NULL && compression >= 0) {
                fprintf(stderr, "Compression level set, but no compression type was defined, setting to gzip\n");
                compress_type = TRACE_OPTION_COMPRESSTYPE_ZLIB;
        }

        else if (compress_type_str == NULL) {
                /* If a level or type is not specified, use the "none"
                 * compression module */
                compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;
        }

        /* I decided to be fairly generous in what I accept for the
         * compression type string */
        else if (strncmp(compress_type_str, "gz", 2) == 0 ||
                        strncmp(compress_type_str, "zlib", 4) == 0) {
                compress_type = TRACE_OPTION_COMPRESSTYPE_ZLIB;
        } else if (strncmp(compress_type_str, "bz", 2) == 0) {
                compress_type = TRACE_OPTION_COMPRESSTYPE_BZ2;
        } else if (strncmp(compress_type_str, "lzo", 3) == 0) {
                compress_type = TRACE_OPTION_COMPRESSTYPE_LZO;
        } else if (strncmp(compress_type_str, "xz", 2) == 0) {
                compress_type = TRACE_OPTION_COMPRESSTYPE_LZMA;
        } else if (strncmp(compress_type_str, "no", 2) == 0) {
                compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;
        } else {
                fprintf(stderr, "Unknown compression type: %s\n",
                        compress_type_str);
                return 1;
        }


	output=trace_create_output(argv[optind++]);
	if (trace_is_err_output(output)) {
		trace_perror_output(output,"trace_create_output");
		return 1;
	}

	if (compression >= 0 && 
			trace_config_output(output, 
			TRACE_OPTION_OUTPUT_COMPRESS, &compression) == -1) {
		trace_perror_output(output,"Unable to set compression level");
		return 1;
	}

	if (trace_config_output(output, TRACE_OPTION_OUTPUT_COMPRESSTYPE,
			&compress_type) == -1) {
		trace_perror_output(output, "Unable to set compression method");
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
					trace_perror(input[i], "%s", argv[i+2]);
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
