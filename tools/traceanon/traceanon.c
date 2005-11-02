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


void usage(char *argv0)
{
	fprintf(stderr,"Usage:\n"
	"%s flags inputfile outputfile\n"
	"-s --encrypt-source	Encrypt the source addresses\n"
	"-d --encrypt-dest	Encrypt the destination addresses\n"
	"-c --cryptopan=key	Encrypt the addresses with the cryptopan\n"
	"			prefix preserving\n"
	"-p --prefix=C.I.D.R/bits Substitute the prefix of the address\n"
	,argv0);
	exit(1);
}

// Incrementally update a checksum
void update_in_cksum(uint16_t *csum, uint16_t old, uint16_t new)
{
	uint32_t sum = (~htons(*csum) & 0xFFFF) 
		     + (~htons(old) & 0xFFFF) 
		     + htons(new);
	sum = (sum & 0xFFFF) + (sum >> 16);
	*csum = htons(~(sum + (sum >> 16)));
}

void update_in_cksum32(uint16_t *csum, uint32_t old, uint32_t new)
{
	update_in_cksum(csum,old>>16,new>>16);
	update_in_cksum(csum,old&0xFFFF,new&0xFFFF);
}

/* Ok this is remarkably complicated
 *
 * We want to change one, or the other IP address, while preserving the 
 * checksum.  TCP and UDP both include the faux header in their checksum
 * calculations, so you have to update them too.  ICMP is even worse --
 * it can include the original IP packet that caused the error!  So anonymise
 * that too, but remember that it's travelling in the opposite direction so
 * we need to encrypt the destination and source instead of the source and
 * destination!
 */
void encrypt_ips(struct libtrace_ip *ip,bool enc_source,bool enc_dest)
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
		if (tcp) update_in_cksum(&tcp->check,old_ip,new_ip);
		if (udp) update_in_cksum(&udp->check,old_ip,new_ip);
		ip->ip_src.s_addr = new_ip;
	}

	if (enc_dest) {
		uint32_t old_ip=ip->ip_dst.s_addr;
		uint32_t new_ip=htonl(enc_ip(
					htonl(ip->ip_dst.s_addr)
					));
		update_in_cksum32(&ip->ip_sum,old_ip,new_ip);
		if (tcp) update_in_cksum(&tcp->check,old_ip,new_ip);
		if (udp) update_in_cksum(&udp->check,old_ip,new_ip);
		ip->ip_dst.s_addr = new_ip;
	}

	if (icmp) {
		/* These are error codes that return the IP packet internally */
		if (icmp->type == 3 || icmp->type == 5 || icmp->type == 11) {
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
	struct libtrace_packet_t packet;
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
			{ NULL,			0, 0, 0 },
		};

		int c=getopt_long(argc, argv, "sc:dp:",
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
			default:
				fprintf(stderr,"unknown option: %c\n",c);
				usage(argv[0]);

		}

	}

	enc_init(enc_type,key);

	// open input uri
	trace = trace_create(argv[optind]);
	if (!trace) {
		fprintf(stderr,"Cannot open %s\n",argv[optind]);
		trace_perror(argv[optind]);
		return 1;
	}
	
	if (optind == argc) {
		// no output specified, output in same format to stdout
		asprintf(&output,"%s:-","erf");
		writer = trace_output_create(output);
	} else {
		writer = trace_output_create(argv[optind +1]);
	}
	if (!writer) {
		trace_perror("trace_output_create");
		return 1;
	}
	
	
	for(;;) {
		struct libtrace_ip *ipptr;
		int psize;
		if ((psize = trace_read_packet(trace, &packet)) <= 0) {
			break;
		}

		ipptr = trace_get_ip(&packet);

		if (ipptr && (enc_source || enc_dest))
			encrypt_ips(ipptr,enc_source,enc_dest);

		/* TODO: Encrypt IP's in ARP packets */

		trace_write_packet(writer,&packet);
	}
	return 0;
}
