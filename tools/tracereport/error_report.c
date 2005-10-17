#include <netdb.h>
#include <inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"

static uint64_t rx_errors = 0;
static uint64_t ip_errors = 0;

void error_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_ip *ip = trace_get_ip(packet);
	void *link = trace_get_link(packet);
	if (!link) {
		++rx_errors;
	}
	if (ip) {
		if (ntohs(ip->ip_sum)!=0)
			++ip_errors;
	}

}

void error_report(void)
{
	printf("# Errors:\n");
	printf("RX Errors: %" PRIu64 "\n",rx_errors);
	printf("IP Checksum errors: %" PRIu64 "\n",ip_errors);
}
