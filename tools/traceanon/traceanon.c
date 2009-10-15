#define _GNU_SOURCE
#include "libtrace.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include "ipenc.h"


static void usage(char *argv0)
{
	fprintf(stderr,"Usage:\n"
	"%s flags inputfile outputfile\n"
	"-s --encrypt-source	Encrypt the source addresses\n"
	"-d --encrypt-dest	Encrypt the destination addresses\n"
	"-c --cryptopan=key	Encrypt the addresses with the cryptopan\n"
	"			prefix preserving\n"
	"-p --prefix=C.I.D.R/bits Substitute the prefix of the address\n"
	"-H --libtrace-help	Print libtrace runtime documentation\n"
	,argv0);
	exit(1);
}

/* Incrementally update a checksum */
static void update_in_cksum(uint16_t *csum, uint16_t old, uint16_t new)
{
	uint32_t sum = (~htons(*csum) & 0xFFFF) 
		     + (~htons(old) & 0xFFFF) 
		     + htons(new);
	sum = (sum & 0xFFFF) + (sum >> 16);
	*csum = htons(~(sum + (sum >> 16)));
}

static void update_in_cksum32(uint16_t *csum, uint32_t old, uint32_t new)
{
	update_in_cksum(csum,(uint16_t)(old>>16),(uint16_t)(new>>16));
	update_in_cksum(csum,(uint16_t)(old&0xFFFF),(uint16_t)(new&0xFFFF));
}

/* Ok this is remarkably complicated
 *
 * We want to change one, or the other IP address, while preserving
 * the checksum.  TCP and UDP both include the faux header in their
 * checksum calculations, so you have to update them too.  ICMP is
 * even worse -- it can include the original IP packet that caused the
 * error!  So anonymise that too, but remember that it's travelling in
 * the opposite direction so we need to encrypt the destination and
 * source instead of the source and destination!
 */
static void encrypt_ips(struct libtrace_ip *ip,bool enc_source,bool enc_dest)
{
	struct libtrace_tcp *tcp;
	struct libtrace_udp *udp;
	struct libtrace_icmp *icmp;

	tcp=trace_get_tcp_from_ip(ip,NULL);
	udp=trace_get_udp_from_ip(ip,NULL);
	icmp=trace_get_icmp_from_ip(ip,NULL);

	if (enc_source) {
		uint32_t old_ip=ip->ip_src.s_addr;
		uint32_t new_ip=htonl(enc_ip(
					htonl(ip->ip_src.s_addr)
					));
		update_in_cksum32(&ip->ip_sum,old_ip,new_ip);
		if (tcp) update_in_cksum32(&tcp->check,old_ip,new_ip);
		if (udp) update_in_cksum32(&udp->check,old_ip,new_ip);
		ip->ip_src.s_addr = new_ip;
	}

	if (enc_dest) {
		uint32_t old_ip=ip->ip_dst.s_addr;
		uint32_t new_ip=htonl(enc_ip(
					htonl(ip->ip_dst.s_addr)
					));
		update_in_cksum32(&ip->ip_sum,old_ip,new_ip);
		if (tcp) update_in_cksum32(&tcp->check,old_ip,new_ip);
		if (udp) update_in_cksum32(&udp->check,old_ip,new_ip);
		ip->ip_dst.s_addr = new_ip;
	}

	if (icmp) {
		/* These are error codes that return the IP packet
		 * internally 
		 */
		if (icmp->type == 3 
				|| icmp->type == 5 
				|| icmp->type == 11) {
			encrypt_ips(
				(struct libtrace_ip*)icmp+
					sizeof(struct libtrace_icmp),
				enc_dest,
				enc_source);
		}
	}
}

int main(int argc, char *argv[]) 
{
	enum enc_type_t enc_type = ENC_NONE;
	char *key = NULL;
	struct libtrace_t *trace = 0;
	struct libtrace_packet_t *packet = trace_create_packet();
	struct libtrace_out_t *writer = 0;
	bool enc_source = false;
	bool enc_dest 	= false;
	char *output = 0;

	if (argc<2)
		usage(argv[0]);

	while (1) {
		int option_index;
		struct option long_options[] = {
			{ "encrypt-source", 	0, 0, 's' },
			{ "encrypt-dest",	0, 0, 'd' },
			{ "cryptopan",		1, 0, 'c' },
			{ "prefix",		1, 0, 'p' },
			{ "libtrace-help", 	0, 0, 'H' },
			{ NULL,			0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "sc:dp:H",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 's': enc_source=true; break;
			case 'd': enc_dest  =true; break;
			case 'c': 
				  if (key!=NULL) {
					  fprintf(stderr,"You can only have one encryption type and one key\n");
					  usage(argv[0]);
				  }
				  key=strdup(optarg);
				  enc_type = ENC_CRYPTOPAN;
				  break;
			case 'p':
				  if (key!=NULL) {
					  fprintf(stderr,"You can only have one encryption type and one key\n");
					  usage(argv[0]);
				  }
				  key=strdup(optarg);
				  enc_type = ENC_PREFIX_SUBSTITUTION;
				  break;
			case 'H': 
				  trace_help(); 
				  exit(1); 
				  break;
			default:
				fprintf(stderr,"unknown option: %c\n",c);
				usage(argv[0]);

		}

	}

	enc_init(enc_type,key);

	/* open input uri */
	trace = trace_create(argv[optind]);
	if (trace_is_err(trace)) {
		trace_perror(trace,argv[optind]);
		trace_destroy(trace);
		return 1;
	}

	if (optind +1>= argc) {
		/* no output specified, output in same format to
		 * stdout 
		 */
		output = strdup("erf:-");
		writer = trace_create_output(output);
	} else {
		writer = trace_create_output(argv[optind +1]);
	}
	if (trace_is_err_output(writer)) {
		trace_perror_output(writer,"trace_create_output");
		trace_destroy_output(writer);
		trace_destroy(trace);
		return 1;
	}
	
	if (trace_start(trace)==-1) {
		trace_perror(trace,"trace_start");
		return 1;
	}
	if (trace_start_output(writer)==-1) {
		trace_perror_output(writer,"trace_start_output");
	}
	for(;;) {
		struct libtrace_ip *ipptr;
		int psize;
		psize = trace_read_packet(trace, packet);
		if (psize == 0) {
			break;
		}
		if (psize < 0) {
			trace_perror(trace,"read_packet");
			break;
		}

		ipptr = trace_get_ip(packet);

		if (ipptr && (enc_source || enc_dest))
			encrypt_ips(ipptr,enc_source,enc_dest);

		/* TODO: Encrypt IP's in ARP packets */

		if (trace_write_packet(writer,packet)==-1) {
			trace_perror_output(writer,"writer");
			break;
		}
	}
	trace_destroy_packet(packet);
	trace_destroy(trace);
	trace_destroy_output(writer);
	return 0;
}
