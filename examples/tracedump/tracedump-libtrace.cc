#include <libtrace.h>
#include <err.h>
#include <time.h>
#include "tracedump.h"
#include <stdio.h>

int main(int argc,char **argv)
{
	struct libtrace_t *trace = trace_create(argv[1]);
	struct libtrace_packet_t packet;
	struct libtrace_filter_t *filter=NULL;
	
	if (!trace) {
		errx(1,"Failed to open trace");
	}

	if (argc>2)
		filter=trace_bpf_setfilter(argv[2]);

	while(trace_read_packet(trace,&packet)!=-1) {
		time_t sec = (time_t)trace_get_seconds(&packet);
		char *link=(char *)trace_get_link(&packet);
		if (filter && !trace_bpf_filter(filter,&packet))
			continue;

		printf("%s",ctime(&sec));
		per_packet(trace_get_link_type(&packet),
				link,
				packet.size-(link-packet.buffer));
	}

	trace_destroy(trace);
	return 0;
}
