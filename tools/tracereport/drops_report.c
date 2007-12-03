#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include "libtrace.h"
#include "tracereport.h"
#include "report.h"

static uint64_t received_packets = 0;
static uint64_t filtered_packets = 0;
static uint64_t dropped_packets = 0;
static uint64_t accepted_packets = 0;

static bool has_received=false;
static bool has_filtered=false;
static bool has_dropped=false;
static bool has_accepted=false;

void drops_per_trace(libtrace_t *trace)
{
	uint64_t packets;

	packets = trace_get_received_packets(trace);
	if (packets != UINT64_MAX) {
		received_packets+=packets;
		has_received=true;
	}

	packets = trace_get_filtered_packets(trace);
	if (packets != UINT64_MAX) {
		filtered_packets+=packets;
		has_filtered=true;
	}

	packets = trace_get_dropped_packets(trace);
	if (packets != UINT64_MAX) {
		dropped_packets+=packets;
		has_dropped=true;
	}

	packets = trace_get_accepted_packets(trace);
	if (packets != UINT64_MAX) {
		accepted_packets+=packets;
		has_accepted=true;
	}
}


void drops_report(void)
{
	FILE *out = fopen("drop.rpt", "w");
	if (!out) {
		perror("fopen");
		return;
	}
	if (has_received)
		fprintf(out, "Received Packets: %" PRIu64 "\n", received_packets);
	if (has_filtered)
		fprintf(out, "Filtered Packets: %" PRIu64 "\n", filtered_packets);
	if (has_dropped)
		fprintf(out, "Dropped Packets: %" PRIu64 "\n", dropped_packets);

	if (has_accepted)
		fprintf(out, "Accepted Packets: %" PRIu64 "\n", accepted_packets);
	fclose(out);
}
