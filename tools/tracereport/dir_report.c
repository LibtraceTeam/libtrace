#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"
#include "report.h"

static uint64_t dir_bytes[8];
static uint64_t dir_packets[8];

void dir_per_packet(struct libtrace_packet_t *packet)
{
	if (trace_get_direction(packet)==~0U)
		return;
	dir_bytes[trace_get_direction(packet)]+=trace_get_wire_length(packet);
	++dir_packets[trace_get_direction(packet)];
}

void dir_report(void)
{
	int i;
	FILE *out = fopen("dir.rpt", "w");
	if (!out) {
		perror("fopen");
		return;
	}
	fprintf(out, "%-20s \t%12s\t%12s\n","DIRECTION","BYTES","PACKETS");
	for(i=0;i<8;++i) {
		if (!dir_packets[i])
			continue;
		switch(i) {
			case TRACE_DIR_INCOMING: fprintf(out, "%20s:\t%12" PRIu64 "\t%12" PRIu64 "\n",
					"Incoming",dir_bytes[i],dir_packets[i]);
				break;
			case TRACE_DIR_OUTGOING: fprintf(out, "%20s:\t%12" PRIu64 "\t%12" PRIu64 "\n",
					"Outgoing",dir_bytes[i],dir_packets[i]);
				break;
			case TRACE_DIR_OTHER: fprintf(out, "%20s:\t%12" PRIu64 "\t%12" PRIu64 "\n",
					"Other",dir_bytes[i],dir_packets[i]);
				break;
			default: fprintf(out, "%20i:\t%12" PRIu64 "\t%12" PRIu64 "\n",
					i,dir_bytes[i],dir_packets[i]);
				break;
		}
	}
	fclose(out);
}
