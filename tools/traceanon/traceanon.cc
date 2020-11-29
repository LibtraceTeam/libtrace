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
#include <arpa/inet.h>

#ifdef HAVE_LIBCRYPTO
#include <openssl/evp.h>
#endif

#include "traceanon.h"
#include "../tools_yaml.h"

struct libtrace_t *inptrace = NULL;
traceanon_opts_t globalopts;

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
        "-C --config=file       Read configuration from a YAML file\n"
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

void add_port_to_server(traceanon_radius_server_t *server, uint16_t port ){
	traceanon_port_list_t *currPort;
	currPort = (traceanon_port_list_t*) malloc(sizeof(traceanon_port_list_t));
	currPort->port = port;
	currPort->nextport = server->port;
	server->port = currPort;
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
static void encrypt_ips(traceanon_opts_t *opts, Anonymiser *anon,
                struct libtrace_ip *ip) {
	libtrace_icmp_t *icmp=trace_get_icmp_from_ip(ip,NULL);

	if (opts->enc_source_opt) {
		uint32_t new_ip=htonl(anon->anonIPv4(ntohl(ip->ip_src.s_addr)));
		ip->ip_src.s_addr = new_ip;
	}

	if (opts->enc_dest_opt) {
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
			encrypt_ips(opts, anon,
				(struct libtrace_ip*)(ptr+
					sizeof(struct libtrace_icmp)));
		}

		if (opts->enc_source_opt || opts->enc_dest_opt)
			icmp->checksum = 0;
	}
}

static void encrypt_ipv6(traceanon_opts_t *opts, Anonymiser *anon,
                libtrace_ip6_t *ip6) {

        uint8_t previp[16];

	if (opts->enc_source_opt) {
                memcpy(previp, &(ip6->ip_src.s6_addr), 16);
		anon->anonIPv6(previp, (uint8_t *)&(ip6->ip_src.s6_addr));
	}

	if (opts->enc_dest_opt) {
                memcpy(previp, &(ip6->ip_dst.s6_addr), 16);
		anon->anonIPv6(previp, (uint8_t *)&(ip6->ip_dst.s6_addr));
	}

}

//ignoring all else, takes a pointer to the start of a radius packet and Anonymises the values in the AVP section.
static void encrypt_radius(traceanon_opts_t *opts, Anonymiser *anon,
                uint8_t *radstart, uint32_t *rem) {

	uint8_t *digest_buffer;
	uint8_t *radius_ptr = radstart + sizeof(radius_header_t);
	radius_header_t *radius_header = (radius_header_t *)radstart;
	uint16_t radius_length = ntohs(radius_header->length);
	uint8_t *radius_end = (radstart+radius_length);

	if (*rem > radius_length){
		//TODO handle error
		return;
	}

	while (radius_ptr < radius_end){
		radius_avp_t *radius_avp = (radius_avp_t*)radius_ptr;
		uint16_t val_len = radius_avp->length-2;

		bool skipAVP = false;
                uint8_t anon_mode = RADIUS_ANON_MODE_BINARY;

		//TODO maybe decide to do more things to different types?
		switch (radius_avp->type) {
			case 6:
			case 7:
			case 40 ... 43:
			case 46 ... 48:
			case 55:
                        case 61:
			{	//skip the above types
				skipAVP = true;
				break;
			}
                        case 1:
                        case 32:
                                anon_mode = RADIUS_ANON_MODE_TEXT;
                                break;
                        case 44:
                                anon_mode = RADIUS_ANON_MODE_NUMERIC;
                                break;

			case 85:{
				//check for access-accept messages
				if (radius_header->code == 2){
					skipAVP = true;
				}
				break;
			}
			
			case 26 : {	//process VSA (assuming there is exactly 1 VSA per AVP of type 26) //TODO?
				radius_ptr += 6;
				radius_avp = (radius_avp_t*)radius_ptr;
				val_len = radius_avp->length-2;
				break;
			}

			default: {
				break;
			}
		}

		if (val_len > 0 && (!skipAVP || opts->radius_force_anon)){
                        uint8_t *ptr;
			digest_buffer = anon->digest_message(
                                        &radius_avp->value, val_len, anon_mode);

                        ptr = &(radius_avp->value);

			while (val_len > SHA256_SIZE){
				//overwrite hash digest into AVP value
				memcpy(ptr, digest_buffer, SHA256_SIZE);
                                val_len -= SHA256_SIZE;
                                ptr += SHA256_SIZE;
			}
			memcpy(ptr, digest_buffer, val_len);
		}
		radius_ptr+=(radius_avp->length); //move to next
	}
}

//retrives radius header from UDP packet
static inline void *find_radius_start(libtrace_packet_t *pkt, uint32_t *rem) {

	void *transport, *radstart;
	uint8_t proto;

	transport = trace_get_transport(pkt, &proto, rem);
	if (!transport || rem == 0) {
		return NULL;
	}

	if (proto != TRACE_IPPROTO_UDP) { //TODO handle TCP radius packets, is that even a thing?
		return NULL;
	}

	radstart = trace_get_payload_from_udp((libtrace_udp_t *)transport, rem);
	return radstart;
}

//checks packets with matching IPs for matching port and encrypts 
int radius_ip_match(traceanon_opts_t *opts,
		libtrace_packet_t *packet,
		Anonymiser *anon,
		uint16_t testPort){

	traceanon_port_list_t *currPort = (opts->radius_server.port);

        while(currPort != NULL){
                if (testPort == currPort->port) {
                        uint32_t rem;
                        uint8_t *radstart = (uint8_t *)find_radius_start(
                                        packet, &rem);
                        if (radstart !=  NULL){
                                encrypt_radius(opts, anon, radstart, &rem);
                                return 1;
                        }
                        break;
                }
                currPort = currPort->nextport;
        }
	return 0;

}

//checks if packet src/dest is filtered for RADIUS and anonymised/encrypted as needed
static void check_radius(libtrace_udp_t *udp, struct libtrace_ip *ipptr,
                libtrace_packet_t *packet, Anonymiser *anon,
                traceanon_opts_t *opts) {

	uint16_t testPort = 0;

        if (udp == NULL) {
                return;
        }

        /* Failure to byteswap port numbers here is intentional. Instead,
         * we've byteswapped the port given in the config file; this means
         * we do less byteswap operations.
         */
        if(ipptr->ip_src.s_addr == opts->radius_server.ipaddr.s_addr){
                testPort = udp->source;
                if (radius_ip_match(opts, packet, anon, testPort))
                        return;
        }

        if(ipptr->ip_dst.s_addr == opts->radius_server.ipaddr.s_addr){
                testPort = udp->dest;
                if (radius_ip_match(opts, packet, anon, testPort))
                        return;
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
        traceanon_opts_t *opts = (traceanon_opts_t *)global;

        if (IS_LIBTRACE_META_PACKET(packet))
                return packet;

        ipptr = trace_get_ip(packet);
        ip6 = trace_get_ip6(packet);
        udp = trace_get_udp(packet);

	if (opts->enc_radius_packet){
		check_radius(udp, ipptr, packet, anon, opts);
	}

        if (ipptr && (opts->enc_source_opt || opts->enc_dest_opt)) {
                encrypt_ips(opts, anon, ipptr);
                ipptr->ip_sum = 0;
        } else if (ip6 && (opts->enc_source_opt || opts->enc_dest_opt)) {
                encrypt_ipv6(opts, anon, ip6);
        }


        /* Replace checksums so that IP encryption cannot be
         * reversed -- TODO allow checksums to be updated and remain valid
         * for the new addresses */

        /* XXX replace with nice use of trace_get_transport() */

        if (udp && (opts->enc_source_opt || opts->enc_dest_opt)) {
                udp->check = 0;
        }

        tcp = trace_get_tcp(packet);
        if (tcp && (opts->enc_source_opt || opts->enc_dest_opt)) {
                tcp->check = 0;
        }

        icmp6 = trace_get_icmp6(packet);
        if (icmp6 && (opts->enc_source_opt || opts->enc_dest_opt)) {
                icmp6->checksum = 0;
        }

        /* TODO: Encrypt IP's in ARP packets */
        result.pkt = packet;
        trace_publish_result(trace, t, trace_packet_get_order(packet), result,
                        RESULT_PACKET);

        return NULL;
}

static void *start_anon(libtrace_t *trace, libtrace_thread_t *t, void *global)
{
        traceanon_opts_t *opts = (traceanon_opts_t *)global;

        if (opts->enc_type == ENC_PREFIX_SUBSTITUTION) {
                PrefixSub *sub = new PrefixSub(opts->enc_key, NULL, opts->salt);
                return sub;
        }

        if (opts->enc_type == ENC_CRYPTOPAN) {
		if (strlen(opts->enc_key) < 32) {
			fprintf(stderr, "ERROR: Key must be at least 32 "
			"characters long for CryptoPan anonymisation.\n");
			exit(1);
		}
#ifdef HAVE_LIBCRYPTO
                CryptoAnon *anon = new CryptoAnon((uint8_t *)opts->enc_key,
                        (uint8_t)strlen(opts->enc_key), 20, opts->salt);
                return anon;
#else
                /* TODO nicer way of exiting? */
                fprintf(stderr, "Error: requested CryptoPan anonymisation but "
                        "libtrace was built without libcrypto support!\n");
                exit(1);
#endif
        }

	if (opts->enc_radius_packet){
		Anonymiser *anon = new Anonymiser(opts->salt);
		return anon;
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
	traceanon_opts_t *opts = (traceanon_opts_t *)global;

        writer = trace_create_output(opts->outputuri);

        if (trace_is_err_output(writer)) {
		trace_perror_output(writer,"trace_create_output");
		trace_destroy_output(writer);
		return NULL;
	}
	
	/* Hopefully this will deal nicely with people who want to crank the
	 * compression level up to 11 :) */
	if (opts->level > 9) {
		fprintf(stderr, "WARNING: Compression level > 9 specified, setting to 9 instead\n");
		opts->level = 9;
	}

	if (opts->level >= 0 && trace_config_output(writer, 
			TRACE_OPTION_OUTPUT_COMPRESS, &(opts->level)) == -1) {
		trace_perror_output(writer, "Configuring compression level");
		trace_destroy_output(writer);
		return NULL;
	}

	if (trace_config_output(writer, TRACE_OPTION_OUTPUT_COMPRESSTYPE,
				&(opts->compress_type)) == -1) {
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

static void init_global_opts(traceanon_opts_t *glob) {
        glob->enc_source_opt = false;
        glob->enc_dest_opt = false;
        glob->enc_type = ENC_NONE;
        glob->enc_key = NULL;

        glob->enc_radius_packet = false;
        glob->radius_force_anon = false;
        memset(glob->salt, 0, SALT_LENGTH);
        glob->isSaltSet = false;
        memset(&(glob->radius_server), 0, sizeof(traceanon_radius_server_t));

        glob->level = 0;
        glob->compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;
        glob->threads = 1;
        glob->filterstring = NULL;
        glob->outputuri = NULL;
}

static void free_global_opts(traceanon_opts_t *glob) {

	traceanon_port_list_t *currPort = glob->radius_server.port;
	traceanon_port_list_t *tempPort;

	while(currPort != NULL){
		tempPort = currPort;
		currPort = currPort->nextport;
		free(tempPort);
	}

        if (glob->enc_key) {
                free(glob->enc_key);
        }

        if (glob->filterstring) {
                free(glob->filterstring);
        }

        if (glob->outputuri) {
                free(glob->outputuri);
        }
}

#define WARN_DEPRECATED fprintf(stderr, \
        "warning: CLI option -%c has been deprecated -- use YAML configuration instead\n", c);

int main(int argc, char *argv[]) 
{
	//struct libtrace_t *trace = 0;
	struct sigaction sigact;
        libtrace_callback_set_t *pktcbs = NULL;
        libtrace_callback_set_t *repcbs = NULL;
        int exitcode = 0;
        libtrace_filter_t *filter = NULL;
        char *configfile = NULL;

	if (argc<2)
		usage(argv[0]);

        init_global_opts(&globalopts);

	while (1) {
                /* For backwards compatibility, I'm keeping the old CLI
                 * arguments working (with warning about deprecation), but
                 * any new config should be added to the config file only.
                 */

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
                        { "config",             1, 0, 'C' },
			{ NULL,			0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "Z:z:sc:f:dp:ht:f:C:",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 'Z':
                                WARN_DEPRECATED
                                globalopts.compress_type = yaml_compress_type(optarg);
                                break;

      			case 'z': WARN_DEPRECATED
                                globalopts.level = atoi(optarg); break;
			case 's': WARN_DEPRECATED;
                                globalopts.enc_source_opt=true; break;
			case 'd': WARN_DEPRECATED
                                globalopts.enc_dest_opt  =true; break;
			case 'c': 
                                WARN_DEPRECATED
                                if (globalopts.enc_key!=NULL) {
                                        fprintf(stderr,"You can only have one encryption type and one key\n");
                                        usage(argv[0]);
                                }
                                globalopts.enc_key=strdup(optarg);
                                globalopts.enc_type = ENC_CRYPTOPAN;
                                break;
		        case 'F': {
                                  WARN_DEPRECATED
			          if (globalopts.enc_key != NULL) {
				    fprintf(stderr,"You can only have one encryption type and one key\n");
				    usage(argv[0]);
				  }
				  FILE * infile = fopen(optarg,"rb");
				  if(infile == NULL) {
				    perror("Failed to open cryptopan keyfile");
                                    return 1;
				  }
				  globalopts.enc_key = (char *) malloc(sizeof(char *) * 32);
				  if(fread(globalopts.enc_key, 1, 32,
                                                infile) != 32) {
				    if(ferror(infile)) {
				      perror("Failed while reading cryptopan keyfile");
				    }
				  }
				  fclose(infile);
				  globalopts.enc_type = ENC_CRYPTOPAN;
				  break;
                        }
                        case 'f':
                                  WARN_DEPRECATED
                                  globalopts.filterstring = strdup(optarg);
                                  break;
		        case 'p':
                                  WARN_DEPRECATED
				  if (globalopts.enc_key!=NULL) {
					  fprintf(stderr,"You can only have one encryption type and one key\n");
					  usage(argv[0]);
				  }
				  globalopts.enc_key=strdup(optarg);
				  globalopts.enc_type = ENC_PREFIX_SUBSTITUTION;
				  break;
			case 'h':
                                  usage(argv[0]);
                        case 't':
                                  WARN_DEPRECATED
                                  globalopts.threads=atoi(optarg);
                                  if (globalopts.threads <= 0)
                                          globalopts.threads = 1;
                                  break;
                        case 'C':
                                  configfile = optarg;
                                  break;

			default:
				fprintf(stderr,"unknown option: %c\n",c);
				usage(argv[0]);

		}

	}

        if (configfile != NULL) {
                if (yaml_parser(configfile, &globalopts,
                                traceanon_yaml_parser) < 0) {
                        fprintf(stderr, "Error reading YAML configuration file, halting.");
                        goto exitanon;
                }
        }

	if (globalopts.compress_type == TRACE_OPTION_COMPRESSTYPE_NONE &&
                        globalopts.level >= 0) {
                fprintf(stderr, "Compression level set, but no compression type was defined, setting to gzip\n");
                globalopts.compress_type = TRACE_OPTION_COMPRESSTYPE_ZLIB;
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
		globalopts.outputuri = strdup("erf:-");
	} else {
		globalopts.outputuri = strdup(argv[optind +1]);
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

        trace_set_perpkt_threads(inptrace, globalopts.threads);

        if (globalopts.filterstring) {
                filter = trace_create_filter(globalopts.filterstring);
        }

        if (filter && trace_config(inptrace, TRACE_OPTION_FILTER, filter) == -1)
        {
                trace_perror(inptrace, "Configuring input filter");
                exitcode = 1;
                goto exitanon;
        }

	if (trace_pstart(inptrace, &globalopts, pktcbs, repcbs)==-1) {
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

        free_global_opts(&globalopts);

	return exitcode;
}
