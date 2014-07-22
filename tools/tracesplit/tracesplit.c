#include <libtrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <time.h>

/* Global variables */
struct libtrace_out_t *output = NULL;
uint64_t count=UINT64_MAX;
uint64_t bytes=UINT64_MAX;
uint64_t starttime=0;
uint64_t endtime=UINT64_MAX;
uint64_t interval=UINT64_MAX;
double firsttime=0;
uint64_t pktcount=0;
uint64_t totbytes=0;
uint64_t totbyteslast=0;
uint64_t maxfiles = UINT64_MAX;
uint64_t filescreated = 0;
uint16_t snaplen = 0;
int verbose=0;
int compress_level=-1;
trace_option_compresstype_t compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;
char *output_base = NULL;


static char *strdupcat(char *str,char *app)
{
	str=realloc(str,strlen(str)+strlen(app)+1);
	strncat(str,app,strlen(str) + strlen(app));
	return str;
}

static char *strdupcati(char *str,uint64_t i)
{
	char buffer[64];
	snprintf(buffer,sizeof(buffer),"%" PRIu64,i);
	return strdupcat(str,buffer);
}

static int usage(char *argv0)
{
	printf("Usage:\n"
	"%s flags inputuri [inputuri ... ] outputuri\n"
	"-f --filter=bpf 	only output packets that match filter\n"
	"-c --count=n 		split every n packets\n"
	"-b --bytes=n	 	Split every n bytes received\n"
	"-i --interval=n	Split every n seconds\n"
	"-s --starttime=time 	Start at time\n"
	"-e --endtime=time	End at time\n"
	"-m --maxfiles=n	Create a maximum of n trace files\n"
	"-H --libtrace-help	Print libtrace runtime documentation\n"
	"-S --snaplen		Snap packets at the specified length\n"
	"-v --verbose		Output statistics\n"
	"-z --compress-level	Set compression level\n"
	"-Z --compress-type 	Set compression type\n"
	,argv0);
	exit(1);
}

volatile int done=0;

static void cleanup_signal(int sig)
{
	(void)sig;
	done=1;
	trace_interrupt();
}


/* Return values:
 *  1 = continue reading packets
 *  0 = stop reading packets, cos we're done
 *  -1 = stop reading packets, we've got an error
 */
static int per_packet(libtrace_packet_t *packet) {

	if (trace_get_link_type(packet) == ~0U) {
		fprintf(stderr, "Halted due to being unable to determine linktype - input trace may be corrupt.\n");
		return -1;
	}

	if (snaplen>0) {
		trace_set_capture_length(packet,snaplen);
	}

	if (trace_get_seconds(packet)<starttime) {
		return 1;
	}

	if (trace_get_seconds(packet)>endtime) {
		return 0;
	}

	if (firsttime==0) {
		time_t now = trace_get_seconds(packet);
		if (starttime != 0) {
			firsttime=now-((now - starttime)%interval);
		}
		else {
			firsttime=now;
		}
	}

	if (output && trace_get_seconds(packet)>firsttime+interval) {
		trace_destroy_output(output);
		output=NULL;
		firsttime+=interval;
	}

	if (output && pktcount%count==0) {
		trace_destroy_output(output);
		output=NULL;
	}

	pktcount++;
	totbytes+=trace_get_capture_length(packet);
	if (output && totbytes-totbyteslast>=bytes) {
		trace_destroy_output(output);
		output=NULL;
		totbyteslast=totbytes;
	}
	if (!output) {
		char *buffer;
		bool need_ext=false;
		if (maxfiles <= filescreated) {
			return 0;
		}
		buffer=strdup(output_base);
		if (interval!=UINT64_MAX && maxfiles>1) {
			buffer=strdupcat(buffer,"-");
			buffer=strdupcati(buffer,(uint64_t)firsttime);
			need_ext=true;
		}
		if (count!=UINT64_MAX && maxfiles>1) {
			buffer=strdupcat(buffer,"-");
			buffer=strdupcati(buffer,(uint64_t)pktcount);
			need_ext=true;
		}
		if (bytes!=UINT64_MAX && maxfiles>1) {
			static int filenum=0;
			buffer=strdupcat(buffer,"-");
			buffer=strdupcati(buffer,(uint64_t)++filenum);
			need_ext=true;
		}
		if (need_ext) {
			if (compress_level!=0)
				buffer=strdupcat(buffer,".gz");
		}
		if (verbose>1) {
			fprintf(stderr,"%s:",buffer);
			if (count!=UINT64_MAX)
				fprintf(stderr," count=%" PRIu64,pktcount);
			if (bytes!=UINT64_MAX)
				fprintf(stderr," bytes=%" PRIu64,bytes);
			if (interval!=UINT64_MAX) {
				time_t filetime = firsttime;
				fprintf(stderr," time=%s",ctime(&filetime));
			}
			else {
				fprintf(stderr,"\n");
			}
		}
		output=trace_create_output(buffer);
		if (trace_is_err_output(output)) {
			trace_perror_output(output,"%s",buffer);
			free(buffer);
			return -1;
		}
		if (compress_level!=-1) {
			if (trace_config_output(output,
						TRACE_OPTION_OUTPUT_COMPRESS,
						&compress_level)==-1) {
				trace_perror_output(output,"Unable to set compression level");
			}
		}

		if (trace_config_output(output,
					TRACE_OPTION_OUTPUT_COMPRESSTYPE,
					&compress_type) == -1) {
			trace_perror_output(output, "Unable to set compression type");
		}

		trace_start_output(output);
		if (trace_is_err_output(output)) {
			trace_perror_output(output,"%s",buffer);
			free(buffer);
			return -1;
		}
		free(buffer);
		filescreated ++;
	}

	/* Some traces we have are padded (usually with 0x00), so 
	 * lets sort that out now and truncate them properly
	 */

	if (trace_get_capture_length(packet) 
			> trace_get_wire_length(packet)) {
		trace_set_capture_length(packet,trace_get_wire_length(packet));
	}

	if (trace_write_packet(output,packet)==-1) {
		trace_perror_output(output,"write_packet");
		return -1;
	}

	return 1;

}

int main(int argc, char *argv[])
{
	char *compress_type_str=NULL;
	struct libtrace_filter_t *filter=NULL;
	struct libtrace_t *input = NULL;
	struct libtrace_packet_t *packet = trace_create_packet();
	struct sigaction sigact;
	int i;	
	
	if (argc<2) {
		usage(argv[0]);
		return 1;
	}

	/* Parse command line options */
	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",	   1, 0, 'f' },
			{ "count",	   1, 0, 'c' },
			{ "bytes",	   1, 0, 'b' },
			{ "starttime",	   1, 0, 's' },
			{ "endtime",	   1, 0, 'e' },
			{ "interval",	   1, 0, 'i' },
			{ "libtrace-help", 0, 0, 'H' },
			{ "maxfiles", 	   1, 0, 'm' },
			{ "snaplen",	   1, 0, 'S' },
			{ "verbose",       0, 0, 'v' },
			{ "compress-level", 1, 0, 'z' },
			{ "compress-type", 1, 0, 'Z' },
			{ NULL, 	   0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "f:c:b:s:e:i:m:S:Hvz:Z:",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 'f': filter=trace_create_filter(optarg);
				break;
			case 'c': count=atoi(optarg);
				break;
			case 'b': bytes=atoi(optarg);
				break;
			case 's': starttime=atoi(optarg); /* FIXME: use getdate */
				  break;
			case 'e': endtime=atoi(optarg);
				  break;
			case 'i': interval=atoi(optarg);
				  break;
			case 'm': maxfiles=atoi(optarg);
				  break;
			case 'S': snaplen=atoi(optarg);
				  break;
			case 'H':
				  trace_help();
				  exit(1);
				  break;
			case 'v':
				  verbose++;
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
	} else if (strncmp(compress_type_str, "xz", 2) == 0) {
		compress_type = TRACE_OPTION_COMPRESSTYPE_LZMA;
	} else if (strncmp(compress_type_str, "no", 2) == 0) {
		compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;
	} else {
		fprintf(stderr, "Unknown compression type: %s\n", 
			compress_type_str);
		return 1;
	}

	if (optind+2>argc) {
		fprintf(stderr,"missing inputuri or outputuri\n");
		usage(argv[0]);
	}

	output_base = argv[argc - 1];

	sigact.sa_handler = cleanup_signal;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = SA_RESTART;

	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);

	output=NULL;

	signal(SIGINT,&cleanup_signal);
	signal(SIGTERM,&cleanup_signal);

	for (i = optind; i < argc - 1; i++) {


		input = trace_create(argv[i]);	
		
		if (trace_is_err(input)) {
			trace_perror(input,"%s",argv[i]);
			return 1;
		}

		if (filter && trace_config(input, TRACE_OPTION_FILTER, filter) == 1) {
			trace_perror(input, "Configuring filter for %s", 
					argv[i]);
			return 1;
		}

		if (trace_start(input)==-1) {
			trace_perror(input,"%s",argv[i]);
			return 1;
		}

		while (trace_read_packet(input,packet)>0) {
			if (per_packet(packet) < 1)
				done = 1;
			if (done)
				break;
		}

		if (trace_is_err(input)) {
			trace_perror(input,"Reading packets");
			trace_destroy(input);
			break;
		}

		trace_destroy(input);
		
		if (done)
			break;
		
	}

	if (verbose) {
		uint64_t f;
		f=trace_get_received_packets(input);
		if (f!=UINT64_MAX)
			fprintf(stderr,"%" PRIu64 " packets on input\n",f);
		f=trace_get_filtered_packets(input);
		if (f!=UINT64_MAX)
			fprintf(stderr,"%" PRIu64 " packets filtered\n",f);
		f=trace_get_dropped_packets(input);
		if (f!=UINT64_MAX)
			fprintf(stderr,"%" PRIu64 " packets dropped\n",f);
		f=trace_get_accepted_packets(input);
		if (f!=UINT64_MAX)
			fprintf(stderr,"%" PRIu64 " packets accepted\n",f);
	}
	
	if (output)
		trace_destroy_output(output);

	trace_destroy_packet(packet);

	return 0;
}
