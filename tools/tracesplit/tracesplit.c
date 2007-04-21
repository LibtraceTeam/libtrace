#include <libtrace.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#endif
#include <lt_inttypes.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

static char *strdupcat(char *str,char *app)
{
	str=realloc(str,strlen(str)+strlen(app)+1);
	strcat(str,app);
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
	"%s flags inputuri outputuri\n"
	"-f --filter=bpf 	only output packets that match filter\n"
	"-c --count=n 		split every n packets\n"
	"-b --bytes=n	 	Split every n bytes received\n"
	"-i --interval=n	Split every n seconds\n"
	"-s --starttime=time 	Start at time\n"
	"-e --endtime=time	End at time\n"
	"-m --maxfiles=n	Create a maximum of n trace files\n"
	"-H --libtrace-help	Print libtrace runtime documentation\n"
	,argv0);
	exit(1);
}

int done=0;

void cleanup_signal(int sig)
{
	done=1;
}

int main(int argc, char *argv[])
{
	struct libtrace_filter_t *filter=NULL;
	struct libtrace_out_t *output = NULL;
	struct libtrace_t *input;
	struct libtrace_packet_t *packet = trace_create_packet();
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
			{ NULL, 	   0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "f:c:b:s:e:i:m:H",
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
			case 'H':
				  trace_help();
				  exit(1);
				  break;
			default:
				fprintf(stderr,"Unknown option: %c\n",c);
				usage(argv[0]);
				return 1;
		}
	}
	if (optind+2<argc) {
		fprintf(stderr,"missing inputuri or outputuri\n");
		usage(argv[0]);
	}

	output=NULL;
	input=trace_create(argv[optind]);
	if (trace_is_err(input)) {
		trace_perror(input,"%s",argv[optind]);
		return 1;
	}

	if (trace_start(input)==-1) {
		trace_perror(input,"%s",argv[optind]);
		return 1;
	}

	signal(SIGINT,&cleanup_signal);
	signal(SIGTERM,&cleanup_signal);

	while(!done) {
		
		if (trace_read_packet(input,packet)<1) {
			break;
		}
		
		if (filter && !trace_apply_filter(filter,packet)) {
			continue;
		}

		if (trace_get_seconds(packet)<starttime) {
			continue;
		}

		if (trace_get_seconds(packet)>endtime) {
			break;
		}

		if (firsttime==0) {
			firsttime=trace_get_seconds(packet);
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
			if (maxfiles <= filescreated) {
				break;
			}
			buffer=strdup(argv[optind+1]);
			if (interval!=UINT64_MAX) {
				buffer=strdupcat(buffer,"-");
				buffer=strdupcati(buffer,(uint64_t)firsttime);
			}
			if (count!=UINT64_MAX) {
				buffer=strdupcat(buffer,"-");
				buffer=strdupcati(buffer,(uint64_t)pktcount);
			}
			if (bytes!=UINT64_MAX) {
				static int filenum=0;
				buffer=strdupcat(buffer,"-");
				buffer=strdupcati(buffer,(uint64_t)++filenum);
			}
			output=trace_create_output(buffer);
			if (trace_is_err_output(output)) {
				trace_perror_output(output,"%s",buffer);
				free(buffer);
				break;
			}
			trace_start_output(output);
			if (trace_is_err_output(output)) {
				trace_perror_output(output,"%s",buffer);
				free(buffer);
				break;
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
			break;
		}

	}

	if (trace_is_err(input)) {
		trace_perror(input, "Reading packets");
	}
	
	trace_destroy(input);
	if (output)
		trace_destroy_output(output);

	trace_destroy_packet(packet);

	return 0;
}
