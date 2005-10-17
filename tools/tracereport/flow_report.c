#include <netdb.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "libtrace.h"
#include "tracereport.h"
#include "tree.h"

static tree_t *flows=NULL;
static uint64_t flow_count=0;

struct fivetuple_t {
	uint32_t ipa;
	uint32_t ipb;
	uint16_t porta;
	uint16_t portb;
	uint8_t prot;
};

static int fivetuplecmp(const void *a, const void *b)
{
	const struct fivetuple_t *as=a;
	const struct fivetuple_t *bs=b;
	if (as->ipa != bs->ipa) return as->ipa-bs->ipa;
	if (as->ipb != bs->ipb) return as->ipb-bs->ipb;
	if (as->porta != bs->porta) return as->porta-bs->porta;
	if (as->portb != bs->portb) return as->portb-bs->portb;
	return as->porta - as->portb;
}

void flow_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_ip *ip = trace_get_ip(packet);
	struct fivetuple_t *ftp;
	if (!ip)
		return;
	ftp=malloc(sizeof(struct fivetuple_t));
	ftp->ipa=ip->ip_src.s_addr;
	ftp->ipb=ip->ip_dst.s_addr;
	ftp->porta=trace_get_source_port(packet);
	ftp->portb=trace_get_destination_port(packet);

	stat_t *stat=tree_find(&flows,ftp,fivetuplecmp);
	if (!stat) {
		stat=calloc(1,sizeof(stat_t));
		++flow_count;
	}

	++stat->count;
	stat->bytes+=trace_get_wire_length(packet);

	if (tree_replace(&flows,ftp,fivetuplecmp,stat)) {
		free(ftp);
	}
}

void flow_report(void)
{
	printf("# Flows:\n");
	printf("Flows: %" PRIu64 "\n",flow_count);
}
