#include <libtrace.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#endif
#include <stdbool.h>
#include <getopt.h>
#include <string.h>

#ifndef UINT64_MAX
# if __WORDSIZE == 64
#  define UINT64_MAX    18446744073709551615UL
# else
#  define UINT64_MAX    18446744073709551615ULL
# endif
#endif

char *strdupcat(char *str,char *app)
{
	str=realloc(str,strlen(str)+strlen(app)+1);
	strcat(str,app);
	return str;
}

char *strdupcati(char *str,int i)
{
	char buffer[64];
	snprintf(buffer,sizeof(buffer),"%i",i);
	return strdupcat(str,buffer);
}

int usage(char *argv)
{
	printf("Usage: %s inputurl [ -c count ] [ -f bpffilter ] [ -b bytes ]\n\t[ -s starttime ] [ -e endtime ] [ -i interval ] outputurl\n",argv);
	printf("\n");
	printf("Splits up traces\n");
	printf("-c count	split every count packets\n");
	printf("-f bpffilter	only output packets that match filter\n");
	printf("-b bytes	split every capture bytes\n");
	printf("-s time		start at starttime\n");
	printf("-e time		end at endtime\n");
	printf("-i seconds	create a new trace every <seconds>\n");
	printf("\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct libtrace_filter_t *filter=NULL;
	struct libtrace_out_t *output = NULL;
	struct libtrace_t *input;
	uint64_t count=UINT64_MAX;
	uint64_t bytes=UINT64_MAX;
	uint64_t starttime=0;
	uint64_t endtime=UINT64_MAX;
	uint64_t interval=UINT64_MAX;
	double firsttime=0;
	uint64_t pktcount=0;
	uint64_t totbytes=0;
	uint64_t totbyteslast=0;

	if (argc<2) {
		usage(argv[0]);
		return 1;
	}

	/* Parse command line options */
	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",	1, 0, 'f' },
			{ "count",	1, 0, 'c' },
			{ "bytes",	1, 0, 'b' },
			{ "starttime",	1, 0, 's' },
			{ "endtime",	1, 0, 'e' },
			{ "interval",	1, 0, 'i' },
			{ NULL, 	0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "f:c:b:s:e:i:",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 'f': filter=trace_bpf_setfilter(optarg);
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

	while(1) {
		struct libtrace_packet_t packet;
		if (trace_read_packet(input,&packet)<1) {
			break;
		}


		if (filter && !trace_bpf_filter(filter,&packet)) {
			continue;
		}

		if (trace_get_seconds(&packet)<starttime) {
			continue;
		}

		if (trace_get_seconds(&packet)>endtime) {
			break;
		}

		if (firsttime==0) {
			firsttime=trace_get_seconds(&packet);
		}

		if (output && trace_get_seconds(&packet)>firsttime+interval) {
			trace_output_destroy(output);
			output=NULL;
			firsttime+=interval;
		}

		pktcount++;
		if (output && pktcount%count==0) {
			trace_output_destroy(output);
			output=NULL;
		}

		totbytes+=trace_get_capture_length(&packet);
		if (output && totbytes-totbyteslast>=bytes) {
			trace_output_destroy(output);
			output=NULL;
			totbyteslast=totbytes;
		}

		if (!output) {
			char *buffer;
			buffer=strdup(argv[optind+1]);
			if (interval!=UINT64_MAX) {
				buffer=strdupcat(buffer,"-");
				buffer=strdupcati(buffer,firsttime);
			}
			if (count!=UINT64_MAX) {
				buffer=strdupcat(buffer,"-");
				buffer=strdupcati(buffer,pktcount);
			}
			if (bytes!=UINT64_MAX) {
				static int filenum=0;
				buffer=strdupcat(buffer,"-");
				buffer=strdupcati(buffer,++filenum);
			}
			output=trace_output_create(buffer);
			free(buffer);
		}

		trace_write_packet(output,&packet);
	}

	if (!output)
		trace_output_destroy(output);

	return 0;
}
