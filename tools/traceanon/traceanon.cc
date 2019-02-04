/*
 *
 * Copyright (c) 2007-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */


#include "config.h"
#include "Anon.h"
#include "libtrace_parallel.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <signal.h>

enum enc_type_t {
        ENC_NONE,
        ENC_CRYPTOPAN,
        ENC_PREFIX_SUBSTITUTION
};

bool enc_source_opt = false;
bool enc_dest_opt   = false;
enum enc_type_t enc_type = ENC_NONE;
char *enc_key = NULL;

int level = -1;
trace_option_compresstype_t compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;

struct libtrace_t *inptrace = NULL;

static void cleanup_signal(int signal)
{
	(void)signal;
	// trace_pstop isn't really signal safe because its got lots of locks in it
        trace_pstop(inptrace);
}

static void usage(char *argv0)
{
	fprintf(stderr,"Usage:\n"
	"%s flags inputfile outputfile\n"
	"-s --encrypt-source	Encrypt the source addresses\n"
	"-d --encrypt-dest	Encrypt the destination addresses\n"
	"-c --cryptopan=key	Encrypt the addresses with the cryptopan\n"
	"			prefix preserving\n"
	"-F --keyfile=file      A file containing the cryptopan key\n"
	"-p --prefix=C.I.D.R/bits Substitute the prefix of the address\n"
	"-h --help	        Print this usage information\n"
	"-z --compress-level	Compress the output trace at the specified level\n"
	"-Z --compress-type 	Compress the output trace using the specified"
	"			compression algorithm\n"
        "-t --threads=max       Use this number of threads for packet processing\n"
        "-f --filter=expr       Discard all packets that do not match the\n"
        "                       provided BPF expression\n"
	,argv0);
	exit(1);
}

/* Incrementally update a checksum */
static void update_in_cksum(uint16_t *csum, uint16_t old, uint16_t newval)
{
	uint32_t sum = (~htons(*csum) & 0xFFFF)
		     + (~htons(old) & 0xFFFF)
		     + htons(newval);
	sum = (sum & 0xFFFF) + (sum >> 16);
	*csum = htons(~(sum + (sum >> 16)));
}

UNUSED static void update_in_cksum32(uint16_t *csum, uint32_t old,
                uint32_t newval)
{
	update_in_cksum(csum,(uint16_t)(old>>16),(uint16_t)(newval>>16));
	update_in_cksum(csum,(uint16_t)(old&0xFFFF),(uint16_t)(newval&0xFFFF));
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
static void encrypt_ips(Anonymiser *anon, struct libtrace_ip *ip,
                bool enc_source,bool enc_dest)
{
	libtrace_icmp_t *icmp=trace_get_icmp_from_ip(ip,NULL);

	if (enc_source) {
		uint32_t new_ip=htonl(anon->anonIPv4(ntohl(ip->ip_src.s_addr)));
		ip->ip_src.s_addr = new_ip;
	}

	if (enc_dest) {
		uint32_t new_ip=htonl(anon->anonIPv4(ntohl(ip->ip_dst.s_addr)));
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
			encrypt_ips(anon,
				(struct libtrace_ip*)(ptr+
					sizeof(struct libtrace_icmp)),
				enc_dest,
				enc_source);
		}

		if (enc_source || enc_dest)
			icmp->checksum = 0;
	}
}

static void encrypt_ipv6(Anonymiser *anon, libtrace_ip6_t *ip6,
                bool enc_source, bool enc_dest) {

        uint8_t previp[16];

	if (enc_source) {
                memcpy(previp, &(ip6->ip_src.s6_addr), 16);
		anon->anonIPv6(previp, (uint8_t *)&(ip6->ip_src.s6_addr));
	}

	if (enc_dest) {
                memcpy(previp, &(ip6->ip_dst.s6_addr), 16);
		anon->anonIPv6(previp, (uint8_t *)&(ip6->ip_dst.s6_addr));
	}

}


static libtrace_packet_t *per_packet(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *tls, libtrace_packet_t *packet) {

	struct libtrace_ip *ipptr;
        libtrace_ip6_t *ip6;
	libtrace_udp_t *udp = NULL;
	libtrace_tcp_t *tcp = NULL;
        libtrace_icmp6_t *icmp6 = NULL;
        Anonymiser *anon = (Anonymiser *)tls;
        libtrace_generic_t result;

        if (IS_LIBTRACE_META_PACKET(packet))
                return packet;

        ipptr = trace_get_ip(packet);
        ip6 = trace_get_ip6(packet);

        if (ipptr && (enc_source_opt || enc_dest_opt)) {
                encrypt_ips(anon, ipptr,enc_source_opt,enc_dest_opt);
                ipptr->ip_sum = 0;
        } else if (ip6 && (enc_source_opt || enc_dest_opt)) {
                encrypt_ipv6(anon, ip6, enc_source_opt, enc_dest_opt);
        }


        /* Replace checksums so that IP encryption cannot be
         * reversed -- TODO allow checksums to be updated and remain valid
         * for the new addresses */

        /* XXX replace with nice use of trace_get_transport() */

        udp = trace_get_udp(packet);
        if (udp && (enc_source_opt || enc_dest_opt)) {
                udp->check = 0;
        }

        tcp = trace_get_tcp(packet);
        if (tcp && (enc_source_opt || enc_dest_opt)) {
                tcp->check = 0;
        }

        icmp6 = trace_get_icmp6(packet);
        if (icmp6 && (enc_source_opt || enc_dest_opt)) {
                icmp6->checksum = 0;
        }

        /* TODO: Encrypt IP's in ARP packets */
        result.pkt = packet;
        trace_publish_result(trace, t, trace_packet_get_order(packet), result, RESULT_PACKET);

        return NULL;
}

static void *start_anon(libtrace_t *trace, libtrace_thread_t *t, void *global)
{
        if (enc_type == ENC_PREFIX_SUBSTITUTION) {
                PrefixSub *sub = new PrefixSub(enc_key, NULL);
                return sub;
        }

        if (enc_type == ENC_CRYPTOPAN) {
		if (strlen(enc_key) < 32) {
			fprintf(stderr, "ERROR: Key must be at least 32 "
			"characters long for CryptoPan anonymisation.\n");
			exit(1);
		}
#ifdef HAVE_LIBCRYPTO                
                CryptoAnon *anon = new CryptoAnon((uint8_t *)enc_key,
                        (uint8_t)strlen(enc_key), 20);
                return anon;
#else
                /* TODO nicer way of exiting? */
                fprintf(stderr, "Error: requested CryptoPan anonymisation but "
                        "libtrace was built without libcrypto support!\n");
                exit(1);
#endif
        }

        return NULL;
}

static void end_anon(libtrace_t *trace, libtrace_thread_t *t, void *global,
                void *tls) {
        Anonymiser *anon = (Anonymiser *)tls;
        delete(anon);

}

static void *init_output(libtrace_t *trace, libtrace_thread_t *t, void *global)
{
        libtrace_out_t *writer = NULL;
        char *outputname = (char *)global;
	
        writer = trace_create_output(outputname);

        if (trace_is_err_output(writer)) {
		trace_perror_output(writer,"trace_create_output");
		trace_destroy_output(writer);
		return NULL;
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
		return NULL;
	}

	if (trace_config_output(writer, TRACE_OPTION_OUTPUT_COMPRESSTYPE,
				&compress_type) == -1) {
		trace_perror_output(writer, "Configuring compression type");
		trace_destroy_output(writer);
		return NULL;
	}

	if (trace_start_output(writer)==-1) {
		trace_perror_output(writer,"trace_start_output");
		trace_destroy_output(writer);
		return NULL;
	}

        return writer;

}

static void write_packet(libtrace_t *trace, libtrace_thread_t *sender,
                      void *global, void *tls, libtrace_result_t *result) {
	libtrace_packet_t *packet = (libtrace_packet_t*) result->value.pkt;
        libtrace_out_t *writer = (libtrace_out_t *)tls;

        if (writer != NULL && trace_write_packet(writer,packet)==-1) {
                trace_perror_output(writer,"writer");
                trace_interrupt();
        }
        trace_free_packet(trace, packet);
}

static void end_output(libtrace_t *trace, libtrace_thread_t *t, void *global,
                void *tls) {
        libtrace_out_t *writer = (libtrace_out_t *)tls;

        trace_destroy_output(writer);
}

int main(int argc, char *argv[]) 
{
	//struct libtrace_t *trace = 0;
	struct sigaction sigact;
	char *output = 0;
	char *compress_type_str=NULL;
        int maxthreads = 4;
        libtrace_callback_set_t *pktcbs = NULL;
        libtrace_callback_set_t *repcbs = NULL;
        int exitcode = 0;
        char *filterstring = NULL;
        libtrace_filter_t *filter = NULL;

	if (argc<2)
		usage(argv[0]);

	while (1) {
		int option_index;
		struct option long_options[] = {
			{ "encrypt-source", 	0, 0, 's' },
			{ "encrypt-dest",	0, 0, 'd' },
			{ "cryptopan",		1, 0, 'c' },
			{ "cryptopan-file",	1, 0, 'F' },
			{ "prefix",		1, 0, 'p' },
			{ "threads",		1, 0, 't' },
			{ "filter",		1, 0, 'f' },
			{ "compress-level",	1, 0, 'z' },
			{ "compress-type",	1, 0, 'Z' },
			{ "help",        	0, 0, 'h' },
			{ NULL,			0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "Z:z:sc:f:dp:ht:f:",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 'Z': compress_type_str=optarg; break;         
			case 'z': level = atoi(optarg); break;
			case 's': enc_source_opt=true; break;
			case 'd': enc_dest_opt  =true; break;
			case 'c': 
				  if (enc_key!=NULL) {
					  fprintf(stderr,"You can only have one encryption type and one key\n");
					  usage(argv[0]);
				  }
				  enc_key=strdup(optarg);
				  enc_type = ENC_CRYPTOPAN;
				  break;
		        case 'F': {
			          if(enc_key != NULL) {
				    fprintf(stderr,"You can only have one encryption type and one key\n");
				    usage(argv[0]);
				  }
				  FILE * infile = fopen(optarg,"rb");
				  if(infile == NULL) {
				    perror("Failed to open cryptopan keyfile");
                                    return 1;
				  }
				  enc_key = (char *) malloc(sizeof(char *) * 32);
				  if(fread(enc_key,1,32,infile) != 32) {
				    if(ferror(infile)) {
				      perror("Failed while reading cryptopan keyfile");
				    }
				  }
				  fclose(infile);
				  enc_type = ENC_CRYPTOPAN;
				  break;
                        }
                        case 'f':
                                  filterstring = optarg;
                                  break;
		        case 'p':
				  if (enc_key!=NULL) {
					  fprintf(stderr,"You can only have one encryption type and one key\n");
					  usage(argv[0]);
				  }
				  enc_key=strdup(optarg);
				  enc_type = ENC_PREFIX_SUBSTITUTION;
				  break;
			case 'h': 
                                  usage(argv[0]);
                        case 't':
                                  maxthreads=atoi(optarg);
                                  if (maxthreads <= 0)
                                          maxthreads = 1;
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
	inptrace = trace_create(argv[optind]);
	if (trace_is_err(inptrace)) {
		trace_perror(inptrace,"trace_create");
		exitcode = 1;
                goto exitanon;
	}

	if (optind +1>= argc) {
		/* no output specified, output in same format to
		 * stdout 
		 */
		output = strdup("erf:-");
	} else {
		output = argv[optind +1];
	}
	// OK parallel changes start here

	/* Set a special mode flag that means the output is timestamped
	 * and ordered before its read into reduce. Seems like a good
	 * special case to have.
	 */
	trace_set_combiner(inptrace, &combiner_ordered, (libtrace_generic_t){0});

        pktcbs = trace_create_callback_set();
        trace_set_packet_cb(pktcbs, per_packet);
        trace_set_stopping_cb(pktcbs, end_anon);
        trace_set_starting_cb(pktcbs, start_anon);

        repcbs = trace_create_callback_set();
        trace_set_result_cb(repcbs, write_packet);
        trace_set_stopping_cb(repcbs, end_output);
        trace_set_starting_cb(repcbs, init_output);

        trace_set_perpkt_threads(inptrace, maxthreads);

        if (filterstring) {
                filter = trace_create_filter(filterstring);
        }

        if (filter && trace_config(inptrace, TRACE_OPTION_FILTER, filter) == -1)
        {
                trace_perror(inptrace, "Configuring input filter");
                exitcode = 1;
                goto exitanon;
        }

	if (trace_pstart(inptrace, output, pktcbs, repcbs)==-1) {
		trace_perror(inptrace,"trace_start");
		exitcode = 1;
                goto exitanon;
	}

	sigact.sa_handler = cleanup_signal;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = SA_RESTART;

	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);

	// Wait for the trace to finish
	trace_join(inptrace);

exitanon:
        if (pktcbs)
                trace_destroy_callback_set(pktcbs);
        if (repcbs)
                trace_destroy_callback_set(repcbs);
        if (inptrace)
        	trace_destroy(inptrace);
	return exitcode;
}
