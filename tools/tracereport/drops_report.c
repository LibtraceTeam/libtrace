#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
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
	libtrace_stat_t *stat;

        stat = trace_create_statistics();

        trace_get_statistics(trace, stat);

	if (stat->received_valid) {
		received_packets+=stat->received;
		has_received=true;
	}

	if (stat->filtered_valid) {
		filtered_packets+=stat->filtered;
		has_filtered=true;
	}

	if (stat->dropped_valid) {
		dropped_packets+=stat->dropped;
		has_dropped=true;
	}

	if (stat->accepted_valid) {
		accepted_packets+=stat->accepted;
		has_accepted=true;
	}
        free(stat);
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
