#include "lib.h"
#include <pcap.h>

struct trace_output_t {
	enum trace_format_t type;
	FILE *f;
	pcap_dumper_t *pcap;
};

struct trace_output_t *create_pcap_output(const char *name)
{
	struct trace_output_t *trace = malloc(sizeof(trace_output_t));
	trace->pcap = pcap_dump_open(NULL,name);
	return trace;
}

int output_packet(struct trace_output_t *trace, struct libtrace_packet_t *packet)
{
}

