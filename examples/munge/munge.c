#define _GNU_SOURCE
#include "libtrace.h"
#include "lib/lib.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <pcap.h>
#include <time.h>

static int trace_link_type_to_dlt(libtrace_linktype_t t)
{
	static int table[] = {
		-1, /* LEGACY */
		-1, /* HDLC over POS */
		DLT_EN10MB, /* Ethernet */
		-1, /* ATM */
		DLT_IEEE802_11, /* 802.11 */
	};
	if (t>sizeof(table)/sizeof(*table)) {
		return -1;
	}
	return table[t];
}

void usage(char *argv0)
{
	fprintf(stderr,"Usage:\n"
	"%s flags inputfile >outputfile\n"
	"-s --encrypt-source	Encrypt the source addresses\n"
	"-d --encrypt-dest	Encrypt the destination addresses\n"
	"-c --cryptopan=key	Encrypt the addresses with the cryptopan\n"
	"			prefix preserving\n"
	"-p --prefix=C.I.D.R/bits Substitute the prefix of the address\n"
	"-f --filter=expr	Apply a tcpdump filter\n"
	"-b --start-time=date	Show only packets after this time\n"
	"-f --end-time=date	Show only packets before this time\n"
	,argv0);
	exit(0);
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

struct libtrace_tcp *get_tcp_from_ip(struct libtrace_ip *ip)
{
#define SW_IP_OFFMASK 0xff1f
	struct libtrace_tcp *tcpptr = 0;

	if ((ip->ip_p == 6) && ((ip->ip_off & SW_IP_OFFMASK) == 0))  {
		tcpptr = (struct libtrace_tcp *)((ptrdiff_t)ip+ (ip->ip_hl * 4));
	}
	return tcpptr;
}

struct libtrace_udp *get_udp_from_ip(struct libtrace_ip *ip)
{
	struct libtrace_udp *udpptr = 0;

	if ((ip->ip_p == 17) && ((ip->ip_off & SW_IP_OFFMASK) == 0))  {
		udpptr = (struct libtrace_udp *)((ptrdiff_t)ip+(ip->ip_hl*4));
	}
	return udpptr;
}

struct libtrace_icmp *get_icmp_from_ip(struct libtrace_ip *ip)
{
	struct libtrace_icmp *icmpptr = 0;

	if ((ip->ip_p == 17) && ((ip->ip_off & SW_IP_OFFMASK) == 0))  {
		icmpptr = (struct libtrace_icmp *)((ptrdiff_t)ip+(ip->ip_hl*4));
	}
	return icmpptr;
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

	tcp=get_tcp_from_ip(ip);
	udp=get_udp_from_ip(ip);
	icmp=get_icmp_from_ip(ip);

	if (enc_source) {
		uint32_t old_ip=ip->ip_src.s_addr;
		uint32_t new_ip=htonl(trace_enc_ip(
					htonl(ip->ip_src.s_addr)
					));
		update_in_cksum32(&ip->ip_sum,old_ip,new_ip);
		if (tcp) update_in_cksum(&tcp->check,old_ip,new_ip);
		if (udp) update_in_cksum(&udp->check,old_ip,new_ip);
		ip->ip_src.s_addr = new_ip;
	}

	if (enc_dest) {
		uint32_t old_ip=ip->ip_dst.s_addr;
		uint32_t new_ip=htonl(trace_enc_ip(
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

struct libtrace_write_t {
	pcap_dumper_t *pcap;
};

void trace_write(struct libtrace_write_t *hdl,struct libtrace_packet_t *pkt)
{
	struct pcap_pkthdr pcap_pkt_hdr;
	void *link = trace_get_link(pkt);

	pcap_pkt_hdr.ts=trace_get_timeval(pkt);
	pcap_pkt_hdr.caplen = trace_get_capture_length(pkt);
	pcap_pkt_hdr.len = trace_get_wire_length(pkt);
	pcap_dump((u_char*)hdl->pcap, &pcap_pkt_hdr, link);
}

double parse_date(const char *date)
{
	struct tm *parsed_time;

	parsed_time=getdate(date);

	if (parsed_time) {
		return (double)mktime(parsed_time);
	}

	switch(getdate_err) {
		case 1:
			fprintf(stderr,"Cannot parse date: The DATEMSK environmental variable is null or undefined\n");
			break;
		case 2:
			fprintf(stderr,"The date template file '%s' cannot be opened for reading\n",getenv("DATEMSK"));
			break;
		case 3:
			fprintf(stderr,"Failed to get file status information for '%s'\n",getenv("DATEMSK"));
			break;
		case 4:
			fprintf(stderr,"%s: Not a regular file\n",getenv("DATEMSK"));
			break;
		case 5:
			fprintf(stderr,"An error occured reading '%s'\n",getenv("DATEMSK"));
			break;
		case 6:
			fprintf(stderr,"Out of memory reading '%s'\n",getenv("DATEMSK"));
			break;
		case 7:
			fprintf(stderr,"Could not parse '%s'\n",date);
			break;
		case 8:
			fprintf(stderr,"Invalid specification in '%s'\n",getenv("DATEMSK"));
			break;
		default:
			fprintf(stderr,"Unable to parse date '%s': Unknown error\n",date);
	}
	exit(1);
}

int main(int argc, char *argv[]) 
{
	enum enc_type_t enc_type = ENC_NONE;
	char *key = NULL;
	struct libtrace_filter_t *filter = NULL;
	struct libtrace_t *trace;
	struct libtrace_packet_t packet;
	struct libtrace_write_t writer;
	bool enc_source = false;
	bool enc_dest 	= false;
	double start_time = 0;
	double end_time = 1e100;
	pcap_t *p = NULL;

	if (argc<2)
		usage(argv[0]);

	while (1) {
		int option_index;
		struct option long_options[] = {
			{ "encrypt-source", 	0, 0, 's' },
			{ "encrypt-dest",	0, 0, 'd' },
			{ "cryptopan",		1, 0, 'c' },
			{ "prefix",		1, 0, 'p' },
			{ "filter",		1, 0, 'f' },
			{ "start-time",		1, 0, 'b' },
			{ "end-time",		1, 0, 'e' },
			{ NULL,			0, 0, 0 },
		};

		int c=getopt_long(argc, argv, "sb:c:de:p:f:",
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
			case 'f':
				  if (filter!=NULL) {
					  fprintf(stderr,"You can only have one filter (use and!)\n");
					  usage(argv[0]);
				  }
				  filter=trace_bpf_setfilter(optarg);
				  break;
			case 'b': /* "begin" time */
				  start_time = parse_date(optarg);
				  break;
			case 'e': /* "end" time */
				  start_time = parse_date(optarg);
				  break;
			default:
				fprintf(stderr,"unknown option: %c\n",c);
				usage(argv[0]);

		}

	}

	trace_enc_init(enc_type,key);

	p = NULL;

	while(optind<argc) {
		/* Do the actual processing */
		trace = trace_create(argv[optind]);
		if (!trace) {
			fprintf(stderr,"Cannot open %s\n",argv[optind]);
			return 1;
		}
		for(;;) {
			struct libtrace_ip *ipptr;
			int psize;
			double ts;
			if ((psize = trace_read_packet(trace, &packet)) <= 0) {
				break;
			}
			if (!p) {
				p=pcap_open_dead(
					trace_link_type_to_dlt(
						trace_get_link_type(&packet)),
					65536);
				writer.pcap = pcap_dump_open(p,"-");
				fflush((FILE *)writer.pcap);
			}

			/* Skip packets that don't match the filter */
			if (filter && !trace_bpf_filter(filter,&packet)) {
				continue;
			}

			ts = trace_get_seconds(&packet);

			/* skip packets before/after the time */
			if (ts < start_time || ts > end_time) {
				continue;
			}

			ipptr = trace_get_ip(&packet);

			if (ipptr && (enc_source || enc_dest))
				encrypt_ips(ipptr,enc_source,enc_dest);

			/* TODO: Encrypt IP's in ARP packets */

			trace_write(&writer,&packet);
		}
		optind++;
	}
	return 0;
}
