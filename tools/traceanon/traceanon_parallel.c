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
#include <assert.h>
#include "ipenc.h"
#include <data-struct/vector.h>
#include <data-struct/message_queue.h>
#include <signal.h>

bool enc_source = false;
bool enc_dest 	= false;
enum enc_type_t enc_type = ENC_NONE;
char *key = NULL;


struct libtrace_t *trace = NULL;

static void cleanup_signal(int signal)
{
	static int s = 0;
	(void)signal;
	// trace_interrupt();
	// trace_pstop isn't really signal safe because its got lots of locks in it
	// trace_pstop(trace);
	if (s == 0) {
		if (trace_ppause(trace) == -1)
			trace_perror(trace, "Pause failed");
	}
	else {
		if (trace_pstart(trace, NULL, NULL, NULL) == -1)
			trace_perror(trace, "Start failed");
	}
	s = !s;
}



static void usage(char *argv0)
{
	fprintf(stderr,"Usage:\n"
	"%s flags inputfile outputfile\n"
	"-s --encrypt-source	Encrypt the source addresses\n"
	"-d --encrypt-dest	Encrypt the destination addresses\n"
	"-c --cryptopan=key	Encrypt the addresses with the cryptopan\n"
	"			prefix preserving\n"
	"-f --keyfile=file      A file containing the cryptopan key\n"
	"-p --prefix=C.I.D.R/bits Substitute the prefix of the address\n"
	"-H --libtrace-help	Print libtrace runtime documentation\n"
	"-z --compress-level	Compress the output trace at the specified level\n"
	"-Z --compress-type 	Compress the output trace using the specified"
	"			compression algorithm\n"
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
			char *ptr = (char *)icmp;
			encrypt_ips(
				(struct libtrace_ip*)(ptr+
					sizeof(struct libtrace_icmp)),
				enc_dest,
				enc_source);
		}

		if (enc_source || enc_dest)
			icmp->checksum = 0;
	}
}


static uint64_t bad_hash(libtrace_packet_t * pkt)
{
	return 0;
}


static uint64_t rand_hash(libtrace_packet_t * pkt)
{
	return rand();
}


static void* per_packet(libtrace_t *trace, libtrace_packet_t *pkt, libtrace_message_t *mesg, libtrace_thread_t *t)
{
	int i;
	
	if (pkt) {
		struct libtrace_ip *ipptr;
		libtrace_udp_t *udp = NULL;
		libtrace_tcp_t *tcp = NULL;

		ipptr = trace_get_ip(pkt);

		if (ipptr && (enc_source || enc_dest)) {
			encrypt_ips(ipptr,enc_source,enc_dest);
			ipptr->ip_sum = 0;
		}

		/* Replace checksums so that IP encryption cannot be
		 * reversed */

		/* XXX replace with nice use of trace_get_transport() */

		udp = trace_get_udp(pkt);
		if (udp && (enc_source || enc_dest)) {
			udp->check = 0;
		} 

		tcp = trace_get_tcp(pkt);
		if (tcp && (enc_source || enc_dest)) {
			tcp->check = 0;
		}

		/* TODO: Encrypt IP's in ARP packets */
		
		// Send our result keyed with the time
		// Arg don't copy packets
		//libtrace_packet_t * packet_copy = trace_copy_packet(packet);
		//libtrace_packet_t * packet_copy = trace_result_packet(trace, pkt);
		//trace_publish_result(trace, trace_packet_get_order(pkt), pkt);
		trace_publish_packet(trace, pkt);
		//return ;
	}
	if (mesg) {
		// printf ("%d.%06d READ #%"PRIu64"\n", tv.tv_sec, tv.tv_usec, trace_packet_get(packet));
		switch (mesg->code) {
			case MESSAGE_STARTED:
				enc_init(enc_type,key);
		}
	}
	return NULL;
}

int main(int argc, char *argv[]) 
{
	//struct libtrace_t *trace = 0;
	struct libtrace_packet_t *packet/* = trace_create_packet()*/;
	struct libtrace_out_t *writer = 0;
	struct sigaction sigact;
	char *output = 0;
	int level = -1;
	char *compress_type_str=NULL;
	trace_option_compresstype_t compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;


	if (argc<2)
		usage(argv[0]);

	while (1) {
		int option_index;
		struct option long_options[] = {
			{ "encrypt-source", 	0, 0, 's' },
			{ "encrypt-dest",	0, 0, 'd' },
			{ "cryptopan",		1, 0, 'c' },
			{ "cryptopan-file",	1, 0, 'f' },
			{ "prefix",		1, 0, 'p' },
			{ "compress-level",	1, 0, 'z' },
			{ "compress-type",	1, 0, 'Z' },
			{ "libtrace-help", 	0, 0, 'H' },
			{ NULL,			0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "Z:z:sc:f:dp:H",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 'Z': compress_type_str=optarg; break;         
			case 'z': level = atoi(optarg); break;
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
		        case 'f':
			          if(key != NULL) {
				    fprintf(stderr,"You can only have one encryption type and one key\n");
				    usage(argv[0]);
				  }
				  FILE * infile = fopen(optarg,"rb");
				  if(infile == NULL) {
				    perror("Failed to open cryptopan keyfile");
                                    return 1;
				  }
				  key = (char *) malloc(sizeof(char *) * 32);
				  if(fread(key,1,32,infile) != 32) {
				    if(ferror(infile)) {
				      perror("Failed while reading cryptopan keyfile");
				    }
				  }
				  fclose(infile);
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

	if (compress_type_str == NULL && level >= 0) {
                fprintf(stderr, "Compression level set, but no compression type was defined, setting to gzip\n");
                compress_type = TRACE_OPTION_COMPRESSTYPE_ZLIB;
        }

        else if (compress_type_str == NULL) {
                /* If a level or type is not specified, use the "none"
                 * compression module */
                compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;
        }

        /* I decided to be fairly generous in what I accept for the
         * compression type string */
        else if (strncmp(compress_type_str, "gz", 2) == 0 ||
                        strncmp(compress_type_str, "zlib", 4) == 0) {
                compress_type = TRACE_OPTION_COMPRESSTYPE_ZLIB;
        } else if (strncmp(compress_type_str, "bz", 2) == 0) {
                compress_type = TRACE_OPTION_COMPRESSTYPE_BZ2;
        } else if (strncmp(compress_type_str, "lzo", 3) == 0) {
                compress_type = TRACE_OPTION_COMPRESSTYPE_LZO;
        } else if (strncmp(compress_type_str, "no", 2) == 0) {
                compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;
        } else {
                fprintf(stderr, "Unknown compression type: %s\n",
                        compress_type_str);
                return 1;
        }
	

	

	/* open input uri */
	trace = trace_create(argv[optind]);
	if (trace_is_err(trace)) {
		trace_perror(trace,"trace_create");
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
	
	/* Hopefully this will deal nicely with people who want to crank the
	 * compression level up to 11 :) */
	if (level > 9) {
		fprintf(stderr, "WARNING: Compression level > 9 specified, setting to 9 instead\n");
		level = 9;
	}

	if (level >= 0 && trace_config_output(writer, 
			TRACE_OPTION_OUTPUT_COMPRESS, &level) == -1) {
		trace_perror_output(writer, "Configuring compression level");
		trace_destroy_output(writer);
		trace_destroy(trace);
		return 1;
	}

	if (trace_config_output(writer, TRACE_OPTION_OUTPUT_COMPRESSTYPE,
				&compress_type) == -1) {
		trace_perror_output(writer, "Configuring compression type");
		trace_destroy_output(writer);
		trace_destroy(trace);
		return 1;
	}

	// OK parallel changes start here

	/* Set a special mode flag that means the output is timestamped
	 * and ordered before its read into reduce. Seems like a good
	 * special case to have.
	 */
	 
	int i = 1;
	trace_parallel_config(trace, TRACE_OPTION_SEQUENTIAL, &i);
	//trace_parallel_config(trace, TRACE_OPTION_SET_PERPKT_BUFFER_SIZE, &i);
	//trace_parallel_config(trace, TRACE_OPTION_USE_DEDICATED_HASHER, &i);
	//trace_parallel_config(trace, TRACE_OPTION_USE_SLIDING_WINDOW_BUFFER, &i);
	i = 2;
	trace_parallel_config(trace, TRACE_OPTION_SET_PERPKT_THREAD_COUNT, &i);
	
	if (trace_pstart(trace, NULL, &per_packet, NULL)==-1) {
		trace_perror(trace,"trace_start");
		trace_destroy_output(writer);
		trace_destroy(trace);
		return 1;
	}
	
	if (trace_start_output(writer)==-1) {
		trace_perror_output(writer,"trace_start_output");
		trace_destroy_output(writer);
		trace_destroy(trace);
                return 1;
	}

	sigact.sa_handler = cleanup_signal;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = SA_RESTART;

	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);
	
	// Read in the resulting packets and then free them when done
	libtrace_vector_t res;
	int res_size = 0;
	libtrace_vector_init(&res, sizeof(libtrace_result_t));
	uint64_t packet_count = 0;
	while (!trace_finished(trace)) {
		// Read messages
		libtrace_message_t message;
		
		// We just release and do work currently, maybe if something
		// interesting comes through we'd deal with that
		libtrace_thread_get_message(trace, &message);
		
		while (libtrace_thread_try_get_message(trace, &message) != LIBTRACE_MQ_FAILED) { }
		
		if ((res_size = trace_get_results(trace, &res)) == 0)
			;/*sched_yield();*/
		
		for (i = 0 ; i < res_size ; i++) {
			libtrace_result_t result;
			assert(libtrace_vector_get(&res, i, (void *) &result) == 1);
			packet = libtrace_result_get_value(&result);
			assert(libtrace_result_get_key(&result) == packet_count);
			packet_count++;
			if (trace_write_packet(writer,packet)==-1) {
				trace_perror_output(writer,"writer");
				trace_interrupt();
				break;
			}
			//trace_destroy_packet(packet);
			trace_free_result_packet(trace, packet);
		}
	}
	trace_join(trace);
	
	// Grab everything that's left here
	res_size = trace_get_results(trace, &res);
	
	for (i = 0 ; i < res_size ; i++) {
		libtrace_result_t result;
		assert(libtrace_vector_get(&res, i, (void *) &result) == 1);
		packet = libtrace_result_get_value(&result);
		if (libtrace_result_get_key(&result) != packet_count)
			printf ("Got a %"PRIu64" but expected a %"PRIu64" %d\n", libtrace_result_get_key(&result), packet_count, res_size);
		assert(libtrace_result_get_key(&result) == packet_count);
		
		packet_count++;
		if (trace_write_packet(writer,packet)==-1) {
			trace_perror_output(writer,"writer");
			trace_interrupt();
			break;
		}
		trace_destroy_packet(packet);
	}
	libtrace_vector_destroy(&res);
	
	//trace_destroy_packet(packet);
	//print_contention_stats(trace);
	trace_destroy(trace);
	trace_destroy_output(writer);
	return 0;
}
