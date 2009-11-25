
/*

  Tracereplay is a simple utility that takes a trace and replays it to a 
  specified interface. 
  It pads packets with zeroes to reach the original length of the packet 
  and recalculates checksums in ip/tcp/udp headers.

  Authors: Andreas Loef and Yuwei Wang


 */




#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <libtrace.h>
#include <getopt.h>
#include <arpa/inet.h>

#define FCS_SIZE 4




/* This function assumes that the relevant fields have been zeroed out. RFC 1071*/
static uint16_t checksum(void * buffer, uint16_t length) {
  uint32_t sum = 0;
  uint16_t * buff = (uint16_t *) buffer;
  uint16_t count = length;

  while(count > 1 ) {
    sum += *buff++;
    count = count -2;
  }

  if(count > 0) {
    sum += *buff;
  }
  
  while (sum>>16)
    sum = (sum & 0xffff) + (sum >> 16);

  return ~sum;
}

static void udp_tcp_checksum(libtrace_ip_t *ip, uint32_t length) {

  uint32_t sum = 0;
  uint16_t protocol = ip->ip_p;
  uint16_t temp = 0;
  uint16_t * check = NULL;
  uint16_t tsum = 0;


  sum += (uint16_t) ~checksum(&ip->ip_src.s_addr,sizeof(uint32_t));
  sum += (uint16_t) ~checksum(&ip->ip_dst.s_addr,sizeof(uint32_t));


  /*this will be in host order whereas everything else is in network order*/
  temp = htons(protocol);
  sum += (uint16_t) ~checksum(&temp,sizeof(uint16_t));

  /*this will be in host order whereas everything else is in network order*/
  temp = htons(length);
  sum += (uint16_t) ~checksum(&temp,sizeof(uint16_t));

  void * transportheader = trace_get_payload_from_ip(ip,NULL,NULL);

  if(protocol == 17 ) {
    libtrace_udp_t * udp_header = transportheader;
    check = &udp_header -> check;
    *check = 0;
    tsum = checksum(transportheader, length);
  }
  else if(protocol == 6) {
    libtrace_tcp_t * tcp_header = transportheader;
    tcp_header -> check = 0;
    check = &tcp_header -> check;
    *check = 0;
    tsum = checksum(transportheader,length);
  }

  sum += (uint16_t) ~tsum;

  while (sum>>16)
    sum = (sum & 0xffff) + (sum >> 16);

  if(check != NULL) {
    *check = (uint16_t)~sum;
  }
  


}


static libtrace_packet_t * per_packet(libtrace_packet_t *packet) {
  uint32_t remaining = 0;  
  libtrace_linktype_t linktype = 0;
  void * pkt_buffer = trace_get_packet_buffer(packet,&linktype,&remaining);
  remaining = 0;
  libtrace_ip_t * header = NULL;
  uint16_t sum = 0;
  libtrace_packet_t *new_packet = trace_create_packet();
  
  size_t wire_length = trace_get_wire_length(packet);

  if(linktype == TRACE_TYPE_ETH || linktype == TRACE_TYPE_80211) {
    wire_length -= FCS_SIZE;
  }

  trace_construct_packet(new_packet,linktype,pkt_buffer,wire_length);
  

  header = trace_get_ip(new_packet);
  if(header != NULL) {
    wire_length -= sizeof(uint32_t)*header->ip_hl;
    header -> ip_sum = 0;
    sum = checksum(header,header->ip_hl*sizeof(uint32_t));
    header -> ip_sum = sum;
    udp_tcp_checksum(header,ntohs(header->ip_len)-sizeof(uint32_t)*header->ip_hl);
  }

  return new_packet;
  
}



static uint32_t event_read_packet(libtrace_t *trace, libtrace_packet_t *packet) 
{
	libtrace_eventobj_t obj;
	fd_set rfds;
	struct timeval sleep_tv;
	
	FD_ZERO(&rfds);
	
	for (;;) {
		obj = trace_event(trace, packet);

		switch(obj.type) {
			
			/* Device has no packets at present - lets wait until
			 * it does get something */
			case TRACE_EVENT_IOWAIT:
				FD_ZERO(&rfds);
				FD_SET(obj.fd, &rfds);
				select(obj.fd + 1, &rfds, NULL, NULL, 0);
				continue;
				
			/* Replaying a trace in tracetime and the next packet
			 * is not due yet */
			case TRACE_EVENT_SLEEP:
				/* select offers good precision for sleeping */
				sleep_tv.tv_sec = (int)obj.seconds;
				sleep_tv.tv_usec = (int) ((obj.seconds - sleep_tv.tv_sec) * 1000000.0);
				select(0, NULL, NULL, NULL, &sleep_tv);
				continue;
				
			/* We've got a packet! */
			case TRACE_EVENT_PACKET:
				/* Check for error first */
				if (obj.size == -1)
					return -1;
				return 1;
				
			/* End of trace has been reached */
			case TRACE_EVENT_TERMINATE:
				return -1;
				
			/* An event we don't know about has occured */
			default:
				fprintf(stderr, "Unknown event type occured\n");
				return -1;
		}
	}
}

static void usage(char * argv) {
	fprintf(stderr, "usage: %s [options] libtraceuri outputuri...\n", argv);
	fprintf(stderr, " --filter bpfexpr\n");
	fprintf(stderr, " -f bpfexpr\n");
	fprintf(stderr, "\t\tApply a bpf filter expression\n");
}

int main(int argc, char *argv[]) {
	
	libtrace_t *trace;
	libtrace_out_t *output;
	libtrace_packet_t *packet;
	libtrace_filter_t *filter=NULL;
	int psize = 0;
	char *uri = 0;

	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",	1, 0, 'f'},
			{ "help",	0, 0, 'h'},
			{ NULL,		0, 0, 0}
		};

		int c = getopt_long(argc, argv, "f:",
				long_options, &option_index);

		if(c == -1)
			break;

		switch (c) {
			case 'f':
				filter = trace_create_filter(optarg);
				break;
			case 'h':
				usage(argv[0]);
				return 1;
			default:
				fprintf(stderr, "Unknown option: %c\n", c);
		}
	}

	if(optind>=argc) {
		fprintf(stderr, "Missing input uri\n");
		usage(argv[0]);
		return 1;
	}
	if(optind+1>=argc) {
		fprintf(stderr, "Missing output uri\n");
		usage(argv[0]);
		return 1;
	}

	uri = strdup(argv[optind]);

	/* Create the trace */
	trace = trace_create(uri);
	if (trace_is_err(trace)) {
		trace_perror(trace, "trace_create");
		return 1;
	}

	/* apply filter */
	if(filter) {
		if(trace_config(trace, TRACE_OPTION_FILTER, filter)) {
			trace_perror(trace, "ignoring: ");
		}
	}

	/* Starting the trace */
	if (trace_start(trace) != 0) {
		trace_perror(trace, "trace_start");
		return 1;
	}

	/* Creating output trace */
	output = trace_create_output(argv[optind+1]);
	
	if (trace_is_err_output(output)) {
		trace_perror_output(output, "Opening output trace: ");
		return 1;
	}
	if (trace_start_output(output)) {
		trace_perror_output(output, "Starting output trace: ");
		trace_destroy_output(output);
		trace_destroy(trace);
		return 1;
	}

	packet = trace_create_packet();

	for (;;) {
		if ((psize = event_read_packet(trace, packet)) <= 0) {
			break;
		}

		/* Got a packet - let's do something with it */
		libtrace_packet_t * new = per_packet(packet);

		if (trace_write_packet(output, new) < 0) {
			trace_perror_output(output, "Writing packet");
			trace_destroy(trace);
			trace_destroy_output(output);
			trace_destroy_packet(packet);
			return 1;
		}
		trace_destroy_packet(new);
	}
	free(uri);
	trace_destroy(trace);
	if(filter != NULL) {
	  trace_destroy_filter(filter);
	}
	trace_destroy_output(output);
	trace_destroy_packet(packet);
	return 0;

}

