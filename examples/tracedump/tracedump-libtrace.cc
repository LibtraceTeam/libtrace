#include <libtrace.h>
#include <err.h>
#include <time.h>
#include "tracedump.h"
#include <stdio.h>

int main(int argc,char **argv)
{
	struct libtrace_t *trace = trace_create(argv[1]);
	struct libtrace_packet_t packet;

	if (!trace) {
		errx(1,"Failed to open trace");
	}

	while(trace_read_packet(trace,&packet)!=-1) {
		time_t sec = (time_t)trace_get_seconds(&packet);
		char *link=(char *)trace_get_link(&packet);
		printf("%s",ctime(&sec));
		per_packet(trace_get_link_type(&packet),
				link,
				packet.size-(link-packet.buffer));
	}

	trace_destroy(trace);
	return 0;
}
