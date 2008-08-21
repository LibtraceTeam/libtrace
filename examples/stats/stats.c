#include "libtrace.h"
#include <inttypes.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include "lt_inttypes.h"

double lastts = 0.0;
uint64_t v4=0;
uint64_t v6=0;
uint64_t udp=0;
uint64_t tcp=0;
uint64_t icmp=0;
uint64_t ok=0;

static void per_packet(libtrace_packet_t *packet)
{
	/* Packet data */
	uint32_t remaining;
	/* L3 data */
	void *l3;
	uint16_t ethertype;
	/* Transport data */
	void *transport;
	uint8_t proto;
	/* Payload data */
	void *payload;

	if (lastts < 1)
		lastts = trace_get_seconds(packet);

	if (lastts+1.0 < trace_get_seconds(packet)) {
		++lastts;
		printf("%.03f,",lastts);
		printf("%"PRIu64",%"PRIu64",",v4,v6);
		printf("%"PRIu64",%"PRIu64",%"PRIu64,icmp,tcp,udp);
		printf("\n");
		v4=v6=0;
		icmp=tcp=udp=0;
	}

 	l3 = trace_get_layer3(packet,&ethertype,&remaining);

	if (!l3)
		/* Probable ARP or something */
		return;

	/* Get the UDP/TCP/ICMP header from the IPv4/IPv6 packet */
	switch (ethertype) {
		case 0x0800:
			transport = trace_get_payload_from_ip(
					(libtrace_ip_t*)l3,
					&proto,
					&remaining);
			if (!transport)
				return;
			++v4;
			break;
		case 0x86DD:
			transport = trace_get_payload_from_ip6(
					(libtrace_ip6_t*)l3,
					&proto,
					&remaining);
			if (!transport)
				return;
			++v6;
			break;
		default:
			return;
	}

	/* Parse the udp/tcp/icmp payload */
	switch(proto) {
		case 1:
			++icmp;
			return;
		case 6:
			payload = trace_get_payload_from_tcp(
					(libtrace_tcp_t*)transport,
					&remaining);
			if (!payload)
				return;

			++tcp;
			break;
		case 17:

			payload = trace_get_payload_from_udp(
					(libtrace_udp_t*)transport,
					&remaining);
			if (!payload)
				return;
			++udp;
			break;
		default:
			return;
	}
	++ok;
}

static void usage(char *argv0)
{
	fprintf(stderr,"usage: %s [ --filter | -f bpfexp ]  [ --snaplen | -s snap ]\n\t\t[ --promisc | -p flag] [ --help | -h ] [ --libtrace-help | -H ] libtraceuri...\n",argv0);
}

int main(int argc, char *argv[])
{
	libtrace_t *trace;
	libtrace_packet_t *packet;
	libtrace_filter_t *filter=NULL;
	int snaplen=-1;
	int promisc=-1;

	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",		1, 0, 'f' },
			{ "snaplen",		1, 0, 's' },
			{ "promisc",		1, 0, 'p' },
			{ "help",		0, 0, 'h' },
			{ "libtrace-help",	0, 0, 'H' },
			{ NULL,			0, 0, 0 }
		};

		int c= getopt_long(argc, argv, "f:s:p:hH",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 'f':
				filter=trace_create_filter(optarg);
				break;
			case 's':
				snaplen=atoi(optarg);
				break;
			case 'p':
				promisc=atoi(optarg);
				break;
			case 'H':
				trace_help();
				return 1;
			default:
				fprintf(stderr,"Unknown option: %c\n",c);
				/* FALL THRU */
			case 'h':
				usage(argv[0]);
				return 1;
		}
	}

	if (optind>=argc) {
		fprintf(stderr,"Missing input uri\n");
		usage(argv[0]);
		return 1;
	}

	while (optind<argc) {
		trace = trace_create(argv[optind]);
		++optind;

		if (trace_is_err(trace)) {
			trace_perror(trace,"Opening trace file");
			return 1;
		}

		if (snaplen>0)
			if (trace_config(trace,TRACE_OPTION_SNAPLEN,&snaplen)) {
				trace_perror(trace,"ignoring: ");
			}
		if (filter)
			if (trace_config(trace,TRACE_OPTION_FILTER,filter)) {
				trace_perror(trace,"ignoring: ");
			}
		if (promisc!=-1) {
			if (trace_config(trace,TRACE_OPTION_PROMISC,&promisc)) {
				trace_perror(trace,"ignoring: ");
			}
		}

		if (trace_start(trace)) {
			trace_perror(trace,"Starting trace");
			trace_destroy(trace);
			return 1;
		}

		packet = trace_create_packet();

		while (trace_read_packet(trace,packet)>0) {
			per_packet(packet);
		}

		trace_destroy_packet(packet);

		if (trace_is_err(trace)) {
			trace_perror(trace,"Reading packets");
		}

		trace_destroy(trace);
	}

	return 0;
}
