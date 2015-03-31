/* Network Capture
 *
 * Creates a file per stream and writes the result to disk
 */
/* Note we include libtrace_parallel.h rather then libtrace.h */
#include "libtrace_parallel.h"
#include <stdio.h>
#include <assert.h>
#include <pthread.h>
#include <inttypes.h>
#include <signal.h>
#include <malloc.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

static char *output = NULL;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int count = 0;
static libtrace_t *trace = NULL;

static int compress_level=-1;
static trace_option_compresstype_t compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;

static void stop(int signal UNUSED)
{
	if (trace)
		trace_pstop(trace);
}

static void usage(char *argv0)
{
	fprintf(stderr,"Usage:\n"
	"%s [options] inputfile outputfile\n"
	"-t --threads	The number of threads to use\n"
	"-S --snaplen	The snap length\n"
	"-H --libtrace-help	Print libtrace runtime documentation\n"
	"-z --compress-level	Compress the output trace at the specified level\n"
	"-Z --compress-type 	Compress the output trace using the specified"
	"			compression algorithm\n"
	,argv0);
	exit(1);
}


static libtrace_out_t *create_output(int my_id) {
	libtrace_out_t *out = NULL;
	char name[1024];
	const char * file_index = NULL;
	const char * first_extension = NULL;

	file_index = strrchr(output, '/');
	if (file_index)
		first_extension = strchr(file_index, '.');
	else
		first_extension = strchr(name, '.');

	if (first_extension) {
		snprintf(name, sizeof(name), "%.*s-%d%s", (int) (first_extension - output), output, my_id, first_extension);
	} else {
		snprintf(name, sizeof(name), "%s-%d", output, my_id);
	}

	out = trace_create_output(name);
	assert(out);

	if (compress_level >= 0 && trace_config_output(out,
			TRACE_OPTION_OUTPUT_COMPRESS, &compress_level) == -1) {
		trace_perror_output(out, "Configuring compression level");
		trace_destroy_output(out);
		exit(-1);
	}

	if (trace_config_output(out, TRACE_OPTION_OUTPUT_COMPRESSTYPE,
				&compress_type) == -1) {
		trace_perror_output(out, "Configuring compression type");
		trace_destroy_output(out);
		exit(-1);
	}

	if (trace_start_output(out)==-1) {
		trace_perror_output(out,"trace_start_output");
		trace_destroy_output(out);
		exit(-1);
	}
	return out;
}

/* Every time a packet becomes ready this function will be called. It will also
 * be called when messages from the library are received. This function
 * is run in parallel.
 */
static void* per_packet(libtrace_t *trace, libtrace_thread_t *t,
                        int mesg, libtrace_generic_t data,
                        libtrace_thread_t *sender UNUSED)
{
	static __thread libtrace_out_t * out;
	static __thread int my_id;
	libtrace_stat_t *stats;

	switch (mesg) {
	case MESSAGE_PACKET:
		trace_write_packet(out, data.pkt);
		/* If we have finished processing this packet return it */
		return data.pkt;
	case MESSAGE_STARTING:
		pthread_mutex_lock(&lock);
		my_id = ++count;
		pthread_mutex_unlock(&lock);
		out = create_output(my_id);
		break;
	case MESSAGE_STOPPING:
		stats = trace_create_statistics();
		trace_get_thread_statistics(trace, t, stats);

		pthread_mutex_lock(&lock);
		fprintf(stderr, "Thread #%d statistics\n", my_id);
		trace_print_statistics(stats, stderr, "\t%s: %"PRIu64"\n");
		pthread_mutex_unlock(&lock);

		free(stats);
		trace_destroy_output(out);
		break;
	default:
		return NULL;
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	struct sigaction sigact;
	libtrace_stat_t *stats;
	int snaplen = -1;
	int nb_threads = -1;
	char *compress_type_str=NULL;

	sigact.sa_handler = stop;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = SA_RESTART;

	sigaction(SIGINT, &sigact, NULL);


	if (argc<3) {
		usage(argv[0]);
		return 1;
	}

	/* Parse command line options */
	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "libtrace-help", 0, 0, 'H' },
			{ "threads",	   1, 0, 't' },
			{ "snaplen",	   1, 0, 'S' },
			{ "compress-level", 1, 0, 'z' },
			{ "compress-type", 1, 0, 'Z' },
			{ NULL, 	   0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "t:S:Hz:Z:",
		                  long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
		case  't': nb_threads = atoi(optarg);
			break;
		case 'S': snaplen=atoi(optarg);
			break;
		case 'H':
			trace_help();
			exit(1);
			break;
		case 'z':
			compress_level=atoi(optarg);
			if (compress_level<0 || compress_level>9) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'Z':
			compress_type_str=optarg;
			break;
		default:
			fprintf(stderr,"Unknown option: %c\n",c);
			usage(argv[0]);
			return 1;
		}
	}

	if (compress_type_str == NULL && compress_level >= 0) {
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
	} else if (strncmp(compress_type_str, "no", 2) == 0) {
		compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;
	} else {
		fprintf(stderr, "Unknown compression type: %s\n",
		        compress_type_str);
		return 1;
	}

	if (argc-optind != 2) {
		usage(argv[0]);
		return 1;
	}
	trace = trace_create(argv[optind]);
	output = argv[optind+1];

	if (trace_is_err(trace)) {
		trace_perror(trace,"Opening trace file");
		return 1;
	}

	if (snaplen != -1)
		trace_set_snaplen(trace, snaplen);
	if(nb_threads != -1)
		trace_set_tick_count(trace, (size_t) nb_threads);

	/* We use a new version of trace_start(), trace_pstart()
	 * The reporter function argument is optional and can be NULL */
	if (trace_pstart(trace, NULL, per_packet, NULL)) {
		trace_perror(trace,"Starting trace");
		trace_destroy(trace);
		return 1;
	}

	/* Wait for the trace to finish */
	trace_join(trace);

	if (trace_is_err(trace)) {
		trace_perror(trace,"Reading packets");
		trace_destroy(trace);
		return 1;
	}

	/* Print stats before we destroy the trace */
	stats = trace_get_statistics(trace, NULL);
	fprintf(stderr, "Overall statistics\n");
	trace_print_statistics(stats, stderr, "\t%s: %"PRIu64"\n");

	trace_destroy(trace);
	return 0;
}
