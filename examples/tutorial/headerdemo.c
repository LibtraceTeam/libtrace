/* A much more complicated libtrace program designed to demonstrate combining
 * various elements of libtrace to create a useful tool.
 *
 * Specifically, this program calculates the amount of header overhead for
 * TCP and UDP traffic compared with the amount of application payload. It
 * writes the byte counts regularly to generate data suitable for a time series
 * graph.
 *
 */
#include "libtrace.h"
#include <stdio.h>
#include <inttypes.h>
#include <err.h>
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>

uint64_t udp_header = 0;
uint64_t udp_payload = 0;
uint64_t tcp_header = 0;
uint64_t tcp_payload = 0;
uint64_t not_ip = 0;

uint32_t next_report = 0;
uint32_t interval = 10;		/* Reporting interval defaults to 10 seconds. */

/* This enum defines values for all the possible protocol cases that this
 * program is interested in */
typedef enum {
	DEMO_PROTO_TCP,		/* The packet is a TCP packet */
	DEMO_PROTO_UDP,		/* The packet is a UDP packet */
	DEMO_PROTO_NOTIP,	/* The packet is NOT an IP packet */
	DEMO_PROTO_OTHER,	/* The packet is none of the above */
	DEMO_PROTO_UNKNOWN	/* Haven't yet determined anything about the
				   packet */
} demo_proto_t;

static void print_stats() {
	printf("%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
		next_report, tcp_header, tcp_payload, udp_header, 
		udp_payload, not_ip);
}

static void check_report(libtrace_packet_t *packet) {
	struct timeval ts;

	/* Get the timestamp for the current packet */
	ts = trace_get_timeval(packet);

	/* If next_report is zero, then this is the first packet from the
	 * trace so we need to determine the time at which the first report 
	 * must occur, i.e. "interval" seconds from now. */

	if (next_report == 0) {
		next_report = ts.tv_sec + interval;

		/* Good opportunity to print some column headings */
		printf("Time,TCP Headers,TCP Payload,UDP Headers,UDP Payload,Not IP\n");
	}

	/* Check whether we need to report our stats
	 *
	 * Compare the timestamp for the current packet against the time that
	 * the next report is due, a la timedemo.c
	 */

	while ((uint32_t)ts.tv_sec > next_report) {
		/* Print all our stats */
		print_stats();

		/* Reset the counters */
		tcp_header = 0;
		tcp_payload = 0;
		udp_header = 0;
		udp_payload = 0;
		not_ip = 0;

		/* Determine when the next report is due */
		next_report += interval;
	}
}

/* Calculates the number of bytes consumed by meta-data headers such as
 * Linux SLL, RadioTap, etc.
 */
static uint64_t calc_meta_size(libtrace_packet_t *packet) {

	uint64_t meta_size = 0;
	void *meta_ptr = NULL;
	libtrace_linktype_t ltype;
	uint32_t remaining;
	uint32_t prev_rem;

	/* Get a pointer to the meta-data header */
	meta_ptr = trace_get_packet_meta(packet, &ltype, &remaining);

	/* If the result is NULL, there are no meta-data headers present */
	if (meta_ptr == NULL) 
		return meta_size;


	/* Skip over any subsequent meta-data headers */
	while (remaining > 0) {
		prev_rem = remaining;
		void *nexthdr = trace_get_payload_from_meta(meta_ptr,
			&ltype, &remaining);

		/* If nexthdr is NULL, the current header is NOT a meta-data
		 * header (and is almost certainly a link layer header) */
		if (nexthdr == NULL) 
			break;
		
		/* Sanity check as remaining should never get larger! */
		assert(prev_rem >= remaining);

		/* Otherwise the header we called get_payload on was a 
		 * meta-data header so we need to add its length to the total
		 * meta header size */	
		meta_size += (prev_rem - remaining);

		/* Prepare ourselves for the next pass through the loop */
		meta_ptr = nexthdr;
	}

	return meta_size;


}

/* Calculates the number of bytes consumed by link layer headers. Note that
 * this will include any "layer 2.5" headers such as MPLS, VLAN or PPP.
 */
static uint64_t calc_link_size(libtrace_packet_t *packet) {
	void *link_ptr;
	void *nexthdr;
	libtrace_linktype_t linktype;
	uint32_t remaining;
	uint32_t prev_rem;
	uint16_t ethertype;

	uint64_t link_size = 0;

	/* Start by finding the layer 2 header */
	link_ptr = trace_get_layer2(packet, &linktype, &remaining);

	/* If there is no layer 2 header, the total link layer has to be
	 * zero bytes in size */
	if (link_ptr == NULL) 
		return link_size;

	/* Calculate the size of the first layer 2 header by comparing
	 * remaining before and after we call trace_get_payload_from_layer2
	 */
	prev_rem = remaining;
	nexthdr = trace_get_payload_from_layer2(link_ptr, linktype, 
			&ethertype, &remaining);

	/* Sanity check - remaining should never get larger! */
	assert(prev_rem >= remaining);
	/* Add the size of the layer 2 header to our overall link layer size */
	link_size += (prev_rem - remaining);

	/* Skip over any layer 2.5 headers, adding their size to our total
	 * link layer size.  */
	while (remaining > 0) {
		if (nexthdr == NULL)
			break;
		prev_rem = remaining;

		/* Ethertype will always contain the type of the current
		 * header that we are up to, thanks to the efforts of the
		 * trace_get_payload_from_* functions */
		switch(ethertype) {
			case 0x8100: 	/* VLAN */
				nexthdr = trace_get_payload_from_vlan(
					nexthdr, &ethertype, &remaining);
				break;
			case 0x8847:	/* MPLS */
				nexthdr = trace_get_payload_from_mpls(
					nexthdr, &ethertype, &remaining);
				break;
			case 0x8864:	/* PPPoE */
				/* This will also skip the PPP header */
				nexthdr = trace_get_payload_from_pppoe(
					nexthdr, &ethertype, &remaining);
				break;
			default:
				/* This is just to provide a stopping condition
				 * for the while loop. */
				nexthdr = NULL;			
		}
		
		/* If we have reached a non-layer 2.5 header, i.e. IP, we 
		 * want to fall out and return the total size */
		if (nexthdr == NULL)
			break;
		
		/* Otherwise, add the length of the skipped header to the
		 * total, being sure to perform our usual sanity check first */
		assert(prev_rem >= remaining);
		link_size += (prev_rem - remaining);
		
	}

	/* Return the total link layer size */
	return link_size;
}

/* Calculates the number of bytes consumed by IP headers, including IPv6 */
static uint64_t calc_ip_size(libtrace_packet_t *packet, demo_proto_t *proto) {

	uint64_t ip_size = 0;
	
	void *ip_hdr;
	void *nexthdr = NULL;;
	uint16_t ethertype;
	uint8_t protocol;
	uint32_t remaining;
	uint32_t prev_rem;
	libtrace_ip6_t *ip6;

	/* Start by finding the first layer 3 header */
	ip_hdr = trace_get_layer3(packet, &ethertype, &remaining);

	/* If no layer 3 headers are present, be sure to set proto 
	 * appropriately so the total header length is added to the right
	 * category */
	if (ip_hdr == NULL) {
		*proto = DEMO_PROTO_NOTIP;
		return ip_size;
	}

	prev_rem = remaining;

	/* Unlike at the link layer, there is less scope for endlessly stacked
	 * headers so we don't need a fancy while loop */

	/* Remember, ethertype tells us the type of the layer 3 header so we
	 * can cast appropriately */
	switch(ethertype) {
		case 0x0800:	/* IPv4 */
			/* Skip past the IPv4 header */
			nexthdr = trace_get_payload_from_ip(ip_hdr, &protocol, 
					&remaining);
			
			/* Check for v6 over v4 and skip over it if present */
			if (nexthdr && protocol == 41) {
				ip6 = (libtrace_ip6_t *)nexthdr;
				nexthdr = trace_get_payload_from_ip6(
					ip6, &protocol, &remaining);
			}
			break;
		case 0x86DD:	/* IPv6 */
			/* Skip past the IPv6 header */
			ip6 = (libtrace_ip6_t *)ip_hdr;
			nexthdr = trace_get_payload_from_ip6(ip6, &protocol, 
					&remaining);
			break;
		default:
			/* Somehow we managed to get a layer 3 header that is
			 * neither v4 nor v6 */
			*proto = DEMO_PROTO_NOTIP;
			return ip_size;
	}

	/* Update our layer 3 size with the number of bytes we just skipped
	 * past */
	assert(prev_rem >= remaining);
	ip_size += (prev_rem - remaining);

	/* We can also use the protocol value from the get_payload function
	 * to determine the transport layer protocol */
	if (protocol == 6) 
		*proto = DEMO_PROTO_TCP;
	else if (protocol == 17)
		*proto = DEMO_PROTO_UDP;
	else
		*proto = DEMO_PROTO_OTHER;
	
	/* Return our total layer 3 size */
	return ip_size;

}

/* Calculates the number of bytes consumed by the transport header, including
 * options etc. */
static uint64_t calc_transport_size(libtrace_packet_t *packet) {
	
	uint64_t trans_size = 0;

	void *transport;
	void *nexthdr;
	uint8_t proto;
	uint32_t remaining;
	uint32_t prev_rem;
	libtrace_tcp_t *tcp;
	libtrace_udp_t *udp;

	/* Start by finding the transport header */
	transport = trace_get_transport(packet, &proto, &remaining);

	/* No transport header makes our life very easy - we can just return
	 * zero */
	if (transport == NULL)
		return trans_size;

	prev_rem = remaining;

	/* Skip past the transport header. Transport headers (at least the ones
	 * we're interested in) can't be stacked so we only ever need to skip
	 * past the one header */

	/* Switch based on the protocol value set by trace_get_transport */
	switch (proto) {
		case 6:		/* TCP */
			tcp = (libtrace_tcp_t *)transport;
			nexthdr = trace_get_payload_from_tcp(tcp, &remaining);
			break;
		case 17:	/* UDP */
			udp = (libtrace_udp_t *)transport;
			nexthdr = trace_get_payload_from_udp(udp, &remaining);
			break;
		default:
			/* We have no interest in ICMP, GRE etc, and we 
			 * should never have entered this function if the
			 * packet is using those protocols anyway! */
			fprintf(stderr, "Unexpected protocol: %u\n", proto);
			return 0;
	}

	/* If we don't have any post-transport payload, just return the 
	 * transport header size */
	if (!nexthdr)
		return trans_size;
	
	/* Determine how many bytes we just skipped over and add it to the
	 * total transport size */
	assert(prev_rem >= remaining);
	trans_size += (prev_rem - remaining);

	/* Return the total size */
	return trans_size;
}

static uint64_t calc_header_size(libtrace_packet_t *packet, demo_proto_t *proto) {

	uint64_t size = 0;

	/* Start with any meta-data headers */
	size += calc_meta_size(packet);

	/* Work out the size of link layer headers */
	size += calc_link_size(packet);

	/* Determine the size of the IP headers */
	size += calc_ip_size(packet, proto);

	/* If the previous function call determined we were not an IP packet,
	 * we can drop out now and return the current size */
	if (*proto == DEMO_PROTO_NOTIP) 
		return size;

	/* We can also drop out if the packet is not using a protocol that we
	 * are interested in */
	if (*proto == DEMO_PROTO_OTHER || *proto == DEMO_PROTO_UNKNOWN)
		return 0;

	/* Add on the transport headers */
	size += calc_transport_size(packet);

	/* Return the total amount of headers */
	return size;
}

static uint64_t calc_payload_size(libtrace_packet_t *packet, demo_proto_t proto)
{

	uint64_t ip_plen = 0;
	uint64_t headers = 0;

	void *layer3;
	uint16_t ethertype;
	uint32_t remaining;

	layer3 = trace_get_layer3(packet, &ethertype, &remaining);

	/* This should NEVER happen, but it's a good habit to check it anyway */
	if (layer3 == NULL)
		return 0;

	/* Find the payload length in the IP header
	 *
	 * We also determine the size of the IP header (again!) as the payload
	 * length includes the IP and transport headers */
	
	if (ethertype == 0x0800) {   /* IPv4 header */
		libtrace_ip_t *ip = (libtrace_ip_t *)layer3;
		
		/* Remember to byte swap! */
		ip_plen = ntohs(ip->ip_len);
		/* This value is only 4 bits so byteswapping is unnecessary */
		headers += (4 * ip->ip_hl);
	
	
	} else if (ethertype == 0x86DD) { /* IPv6 header */
		libtrace_ip6_t *ip = (libtrace_ip6_t *)layer3;
		
		/* Remember to byte swap! */
		ip_plen = ntohs(ip->plen);
		/* IPv6 does not have a variable length header */
		headers += sizeof(libtrace_ip6_t);
	
	
	} else {
		/* Not an IP packet - this should also never happen */
		return 0;
	}

	
	/* Now we need to subtract the size of the transport header from the
	 * IP payload length. */
	if (proto == DEMO_PROTO_TCP) {
		
		/* Determine the size of the TCP header so we can subtract
		 * that from our total payload length */
		
		/* Since I already know the protocol and only need to 
		 * access a single value inside the TCP header, I can use
		 * the trace_get_tcp() helper function instead of the more
		 * verbose trace_get_transport() . */
		libtrace_tcp_t *tcp = trace_get_tcp(packet);
		if (tcp == NULL)
			return 0;

		/* Again, byteswapping not required because the doff field is
		 * only a single byte in size*/
		headers += (tcp->doff * 4);
	}

	if (proto == DEMO_PROTO_UDP) {
		/* UDP has a fixed length header so we don't even need to use
		 * trace_get_udp() */
		headers += sizeof(libtrace_udp_t);
	}

	assert(headers <= ip_plen);

	/* Subtract the length of the IP and transport headers from the 
	 * payload length contained within the IP header */
	return ip_plen - headers;

}

static void per_packet(libtrace_packet_t *packet)
{
	uint64_t header_size = 0;
	uint64_t payload_size = 0;
	demo_proto_t protocol = DEMO_PROTO_UNKNOWN;

	/* Check if we're due to report some stats */
	check_report(packet);

	/* We need to determine the amount of header in this packet */
	header_size = calc_header_size(packet, &protocol);
	
	/* Now determine the payload size, if necessary */
	if (protocol == DEMO_PROTO_TCP || protocol == DEMO_PROTO_UDP) {
		payload_size = calc_payload_size(packet, protocol);
	}

	/* Update the appropriate counters */
	switch(protocol) {
		case DEMO_PROTO_TCP:
			tcp_header += header_size;
			tcp_payload += payload_size;
			break;

		case DEMO_PROTO_UDP:
			udp_header += header_size;
			udp_payload += payload_size;
			break;

		case DEMO_PROTO_NOTIP:
			not_ip += header_size;
			break;

		case DEMO_PROTO_OTHER:
			break;

		case DEMO_PROTO_UNKNOWN:
			break;
	}


}

/* Due to the amount of error checking required in our main function, it
 * is a lot simpler and tidier to place all the calls to various libtrace
 * destroy functions into a separate function.
 */
static void libtrace_cleanup(libtrace_t *trace, libtrace_packet_t *packet, 
		libtrace_filter_t *filter) {
	
	/* It's very important to ensure that we aren't trying to destroy
	 * a NULL structure, so each of the destroy calls will only occur
	 * if the structure exists */
	if (trace)
		trace_destroy(trace);
	
	if (packet)
		trace_destroy_packet(packet);

	if (filter)
		trace_destroy_filter(filter);
}

static void usage(char *prog) {
	fprintf(stderr, "Usage: %s [-i interval] [-f filter] inputURI\n",
		prog);
}


int main(int argc, char *argv[])
{
	libtrace_t *trace = NULL;
	libtrace_packet_t *packet = NULL;
	libtrace_filter_t *filter = NULL;

	int opt;
	char *filterstring = NULL;

	/* Ensure we have at least one argument after the program name */
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	/* Using getopt to handle any command line flags that would set the
	 * reporting interval and a filter */
	while ((opt = getopt(argc, argv, "i:f:")) != EOF) {
		switch (opt) {
			case 'i':
				interval = atoi(optarg);
				break;
			case 'f':
				filterstring = optarg;
				break;
			default:
				usage(argv[0]);
				return 1;
		}
	}
	
	/* After processing the options, we still need an argument to define
	 * the input URI */
	if (optind + 1 > argc) {
		usage(argv[0]);
		return 1;
	}
	
	/* Create the filter if a filter string was provided */
	if (filterstring != NULL) {
		filter = trace_create_filter(filterstring);
		if (filter == NULL) {
			fprintf(stderr, "Failed to create filter (%s)\n",
				filterstring);
			libtrace_cleanup(trace, packet, filter);
			return 1;
		}
	}

	/* Creating and initialising a packet structure to store the packets
	 * that we're going to read from the trace */
	packet = trace_create_packet();

	if (packet == NULL) {
		/* Unfortunately, trace_create_packet doesn't use the libtrace
		 * error system. This is because libtrace errors are associated
		 * with the trace structure, not the packet. In our case, we
		 * haven't even created a trace at this point so we can't 
		 * really expect libtrace to set an error on it for us, can
		 * we?
		 */
		perror("Creating libtrace packet");
		libtrace_cleanup(trace, packet, filter);
		return 1;
	}

	/* Opening and starting the input trace. Note that unlike the other
	 * examples, we can't just use argv[1] as we may have seen command
	 * line options. Instead we should use optind which will be set to
	 * the index of the first non-getopt argument  */
	trace = trace_create(argv[optind]);

	if (trace_is_err(trace)) {
		trace_perror(trace,"Opening trace file");
		libtrace_cleanup(trace, packet, filter);
		return 1;
	}

	/* Apply a filter, if one was created */
	if (filter != NULL) {
		if (trace_config(trace, TRACE_OPTION_FILTER, filter) == -1) {
			trace_perror(trace, "Configuring filter");
			libtrace_cleanup(trace, packet, filter);
			return 1;
		}
	}

	if (trace_start(trace) == -1) {
		trace_perror(trace,"Starting trace");
		libtrace_cleanup(trace, packet, filter);
		return 1;
	}

	/* This loop will read packets from the trace until either EOF is
	 * reached or an error occurs (hopefully the former!)
	 *
	 * Remember, EOF will return 0 so we only want to continue looping
	 * as long as the return value is greater than zero
	 */
	while (trace_read_packet(trace,packet)>0) {
		/* Call our per_packet function for every packet */
		per_packet(packet);
	}

	/* If the trace is in an error state, then we know that we fell out of
	 * the above loop because an error occurred rather than EOF being
	 * reached. Therefore, we should probably tell the user that something
	 * went wrong
	 */
	if (trace_is_err(trace)) {
		trace_perror(trace,"Reading packets");
		libtrace_cleanup(trace, packet, filter);
		return 1;
	}
	
	/* Print out the contents of the counters before exiting */
	print_stats();

	libtrace_cleanup(trace, packet, filter);

	return 0;
}
