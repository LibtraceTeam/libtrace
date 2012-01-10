#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"
#include "report.h"

struct tcp_opts {
	bool mss;
	bool sack;
	bool winscale;
	bool ts;
	bool ttcp;
	bool other;
};

struct opt_counter {
	uint64_t no_options;
	uint64_t mss_only;
	uint64_t ts_only;
	uint64_t ms;
	uint64_t mw;
	uint64_t msw;
	uint64_t mt;
	uint64_t all_four;
	uint64_t ts_and_sack;
	uint64_t wt;
	uint64_t tms;
	uint64_t tws;
	uint64_t tmw;
	uint64_t ts_and_another;
	uint64_t ttcp;
	uint64_t other;
};

struct opt_counter syn_counts = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
struct opt_counter synack_counts = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

uint64_t total_syns = 0;
uint64_t total_synacks = 0;

static void classify_packet(struct tcp_opts opts, struct opt_counter *counts) {
	if (!opts.mss && !opts.sack && !opts.winscale && !opts.ts && !opts.ttcp && !opts.other)
	{
		counts->no_options ++;
		return;
	}

	if (opts.mss && !opts.sack && !opts.winscale && !opts.ts && !opts.ttcp && !opts.other)
	{
		counts->mss_only ++;
		return;
	}

	if (!opts.mss && !opts.sack && !opts.winscale && opts.ts && !opts.ttcp && !opts.other)
	{
		counts->ts_only ++;
		return;
	}

	if (opts.mss && opts.sack && !opts.winscale && !opts.ts)
		counts->ms ++;

	if (opts.mss && opts.winscale && !opts.sack && !opts.ts)
		counts->mw ++;

	if (opts.mss && opts.winscale && opts.sack && !opts.ts)
		counts->msw ++;
	
	if (opts.mss && opts.ts && !opts.winscale && !opts.sack)
		counts->mt ++;
	if (opts.ts && opts.sack && !opts.mss && !opts.winscale)
		counts->ts_and_sack ++;

	if (opts.ts && opts.winscale && !opts.mss && !opts.sack)
		counts->wt ++;

	if (opts.ts && opts.mss && opts.winscale && !opts.sack)
		counts->tmw ++;
	if (opts.ts && opts.mss && opts.sack && !opts.winscale)
		counts->tms ++;
	if (opts.ts && opts.sack && opts.winscale && !opts.mss)
		counts->tws ++;
	
	
	if (opts.mss && opts.sack && opts.winscale && opts.ts) {
		counts->all_four ++;
	}

	if (opts.ts && (opts.mss || opts.winscale || opts.sack)) {
		counts->ts_and_another ++;
	}
	
	if (opts.ttcp)
		counts->ttcp ++;
	if (opts.other)
		counts->other ++;	
}

void synopt_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_tcp *tcp = trace_get_tcp(packet);
	unsigned char *opt_ptr;
	libtrace_direction_t dir = trace_get_direction(packet);
	int len;
	unsigned char type, optlen, *data;
	struct tcp_opts opts_seen = {false, false, false, false, false, false};
	
	if(!tcp)
		return;

	if (!tcp->syn)
		return;
	
	if (dir != TRACE_DIR_INCOMING && dir != TRACE_DIR_OUTGOING)
		dir = TRACE_DIR_OTHER;
	
	len = tcp->doff * 4 - sizeof(libtrace_tcp_t);
	if(len == 0)
		return;
	
	opt_ptr = (unsigned char *)tcp + sizeof (libtrace_tcp_t);
	
	while(trace_get_next_option(&opt_ptr,&len,&type,&optlen,&data)){
		/* I don't think we need to count NO-OPs */
		if (type == 1)
			continue;
		switch(type) {
			case 2:
				opts_seen.mss = true;
				break;
			case 3:
				opts_seen.winscale = true;
				break;
			case 4:
				opts_seen.sack = true;
				break;
			case 5:
				opts_seen.sack = true;
				break;
			case 8:
				opts_seen.ts = true;
				break;
			case 11:
			case 12:
			case 13:
				opts_seen.ttcp = true;
				break;
			default:
				opts_seen.other = true;
		}
	}

	if (tcp->ack) {
		total_synacks ++;
		classify_packet(opts_seen, &synack_counts);
	} else {
		total_syns ++;
		classify_packet(opts_seen, &syn_counts);
	}
}


void synopt_report(void)
{
	
	FILE *out = fopen("tcpopt_syn.rpt", "w");
	if (!out) {
		perror("fopen");
		return;
	}


	
	fprintf(out, "%-20s\t%.2f%%\t%.2f%%\n",
			"No Options",
			(double)(syn_counts.no_options) / total_syns * 100.0,
			(double)(synack_counts.no_options) / total_synacks * 100.0);
	fprintf(out, "%-20s\t%.2f%%\t%.2f%%\n",
			"M Only",
			(double)(syn_counts.mss_only) / total_syns * 100.0,
			(double)(synack_counts.mss_only) / total_synacks * 100.0);
	fprintf(out, "%-20s\t%.2f%%\t%.2f%%\n",
			"T Only",
			(double)(syn_counts.ts_only) / total_syns * 100.0,
			(double)(synack_counts.ts_only) / total_synacks * 100.0);
	fprintf(out, "%-20s\t%.2f%%\t%.2f%%\n",
			"M and S",
			(double)(syn_counts.ms) / total_syns * 100.0,
			(double)(synack_counts.ms) / total_synacks * 100.0);
	fprintf(out, "%-20s\t%.2f%%\t%.2f%%\n",
			"M and W",
			(double)(syn_counts.mw) / total_syns * 100.0,
			(double)(synack_counts.mw) / total_synacks * 100.0);
	fprintf(out, "%-20s\t%.2f%%\t%.2f%%\n",
			"M, S and W",
			(double)(syn_counts.msw) / total_syns * 100.0,
			(double)(synack_counts.msw) / total_synacks * 100.0);
	fprintf(out, "%-20s\t%.2f%%\t%.2f%%\n",
			"M, T",
			(double)(syn_counts.mt) / total_syns * 100.0,
			(double)(synack_counts.mt) / total_synacks * 100.0);
	fprintf(out, "%-20s\t%.2f%%\t%.2f%%\n",
			"W, T",
			(double)(syn_counts.wt) / total_syns * 100.0,
			(double)(synack_counts.wt) / total_synacks * 100.0);
	fprintf(out, "%-20s\t%.2f%%\t%.2f%%\n",
			"S, T",
			(double)(syn_counts.ts_and_sack) / total_syns * 100.0,
			(double)(synack_counts.ts_and_sack) / total_synacks * 100.0);
	fprintf(out, "%-20s\t%.2f%%\t%.2f%%\n",
			"S, M, T",
			(double)(syn_counts.tms) / total_syns * 100.0,
			(double)(synack_counts.tms) / total_synacks * 100.0);
	fprintf(out, "%-20s\t%.2f%%\t%.2f%%\n",
			"W, M, T",
			(double)(syn_counts.tmw) / total_syns * 100.0,
			(double)(synack_counts.tmw) / total_synacks * 100.0);
	fprintf(out, "%-20s\t%.2f%%\t%.2f%%\n",
			"S, W, T",
			(double)(syn_counts.tws) / total_syns * 100.0,
			(double)(synack_counts.tws) / total_synacks * 100.0);
	fprintf(out, "%-20s\t%.2f%%\t%.2f%%\n",
			"M, S, W and T",
			(double)(syn_counts.all_four) / total_syns * 100.0,
			(double)(synack_counts.all_four) / total_synacks * 100.0);
	//fprintf(out, "%-20s\t%.2f%%\n",
	//		"T and (M or S or W)",
	//		(double)(counts.ts_and_another) / total_syns * 100.0);
	fprintf(out, "%-20s\t%.2f%%\t%.2f%%\n",
			"T/TCP",
			(double)(syn_counts.ttcp) / total_syns * 100.0,
			(double)(synack_counts.ttcp) / total_synacks * 100.0);
	fprintf(out, "%-20s\t%.2f%%\t%.2f%%\n",
			"Other options",
			(double)(syn_counts.other) / total_syns * 100.0,
			(double)(synack_counts.other) / total_synacks * 100.0);
	
	
	fclose(out);
}
