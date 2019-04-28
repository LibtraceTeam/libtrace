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

enum enc_type_t {
        ENC_NONE,
        ENC_CRYPTOPAN,
        ENC_PREFIX_SUBSTITUTION
};

bool enc_source_opt = false;
bool enc_dest_opt   = false;
enum enc_type_t enc_type = ENC_NONE;
char *enc_key = NULL;


#define SALT_LENGTH 32
#define SHA256_SIZE 32
bool enc_radius_packet = false;
uint8_t salt[SALT_LENGTH];
bool isSaltSet = false;

typedef struct traceanon_port_list_t{
	uint16_t port;
	traceanon_port_list_t *nextport;
}traceanon_port_list_t;

typedef struct traceanon_radius_server_t {
	struct in_addr ipaddr;
	traceanon_port_list_t *port;
}traceanon_radius_server_t;

traceanon_radius_server_t radius_server;

typedef struct radius_header {
    uint8_t code;
    uint8_t identifier;
    uint16_t length;
    uint8_t auth[16];
} PACKED radius_header_t;

typedef struct radius_avp {
    uint8_t type;
    uint8_t length;
    uint8_t value;
} PACKED radius_avp_t;

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
	"-r --radius-server=a.b.c.d[:port1] Specifies an IP address and\n"
	"				a ':' separated list of ports to\n"
	"                               match for RADIUS anonymising.\n"
	"-R --radius-salt=salt  Use provided salt for RADIUS hashing\n"
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

//ignoring all else, takes a pointer to the start of a radius packet and Anonymises the values in the AVP section.
static void encrypt_radius(Anonymiser *anon, uint8_t *radstart, uint32_t *rem){
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

		//if(radius_avp->type) ;//TODO maybe decide to do different things to different types?
		digest_buffer = anon->digest_message(&radius_avp->value, val_len);

		// printf("TYPE:0x%02x\tLEN:0x%02x\n",radius_avp->type, radius_avp->length);
		// for (uint16_t i = 0; i < val_len; i++){printf("%02x ",*(&radius_avp->value +i));}printf("\n");
		// for (uint16_t i = 0; i < val_len; i++){printf("%02x ",i < 32 ? *(digest_buffer+i):0);}printf("\n");

		if (val_len > SHA256_SIZE){
			memcpy(&radius_avp->value, digest_buffer, SHA256_SIZE);		//overwrite hash digest into AVP value
			memset(&radius_avp->value+SHA256_SIZE, 0, val_len-SHA256_SIZE);	//pad with zeros to fill 
		}
		else {
			memcpy(&radius_avp->value, digest_buffer, val_len);
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
int radius_ip_match(libtrace_udp_t *udp, 
		struct libtrace_ip *ipptr, 
		libtrace_packet_t *packet, 
		Anonymiser *anon, 
		uint16_t testPort){

	traceanon_port_list_t *currPort = (radius_server.port);

	if(testPort != 0){ //an ip matches
		while(currPort != NULL){
			if (testPort == currPort->port){
				uint32_t rem;
				uint8_t *radstart = (uint8_t *)find_radius_start(packet, &rem);
				if (radstart ==  NULL){
					printf("Radius Header Error\n");
					//handle error
				}
				else {
					encrypt_radius(anon, radstart, &rem);
					return 1;
				}
				break;
			}
			currPort = currPort->nextport;
		}
	}
	return 0;

}

//checks if packet src/dest is filtered for RADIUS and anonymised/encrypted as needed
void check_radius(libtrace_udp_t *udp, struct libtrace_ip *ipptr, libtrace_packet_t *packet, Anonymiser *anon){
	udp = trace_get_udp(packet);
	if (udp){	
		uint16_t testPort = 0;
		if(ipptr->ip_src.s_addr == radius_server.ipaddr.s_addr){
			testPort = udp->source;
			if (radius_ip_match(udp, ipptr, packet, anon, testPort))
				return;
		}
		if(ipptr->ip_dst.s_addr == radius_server.ipaddr.s_addr){
			testPort = udp->dest;
			if (radius_ip_match(udp, ipptr, packet, anon, testPort))
				return;
		}
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

	if (enc_radius_packet){
		check_radius(udp, ipptr, packet, anon);
	}

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
                PrefixSub *sub = new PrefixSub(enc_key, NULL, salt);
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
                        (uint8_t)strlen(enc_key), 20, salt);
                return anon;
#else
                /* TODO nicer way of exiting? */
                fprintf(stderr, "Error: requested CryptoPan anonymisation but "
                        "libtrace was built without libcrypto support!\n");
                exit(1);
#endif
        }

	if (enc_radius_packet){
		Anonymiser *anon = new Anonymiser(salt);
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
			{"radius-server", 	1, 0, 'r' },
			{"radius-salt", 	1, 0, 'R' },
			{ NULL,			0, 0, 0   },
		};

		int c=getopt_long(argc, argv, "Z:z:sc:f:dp:ht:f:r:R:",
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
			case 'r':{
				if (radius_server.ipaddr.s_addr != 0){
					fprintf(stderr, "You can only have one radius server at a time\n");
					usage(argv[0]);
				}
				enc_radius_packet = true;
				
				char *token = strtok(optarg, ":");
				struct in_addr ipaddr;

				if(inet_aton(token, &ipaddr) == 0){
					fprintf(stderr, "IP address malformed\n");
					usage(argv[0]);
				}
				radius_server.ipaddr = ipaddr;

				char * garbage = NULL;
				while( (token = strtok(NULL, ":")) != NULL ) {
					in_port_t port = strtol(token, &garbage, 10);
					if(garbage == NULL || (*garbage != ':' && *garbage != 0)){
						fprintf(stderr, "Port list malformed\n");
						usage(argv[0]);
					}
					add_port_to_server(&radius_server,htons(port));
				}
				break;
				}
			case 'R' :{
				if (isSaltSet){
					fprintf(stderr,"Salt has already been set: %c\n",c);
					usage(argv[0]);
				}
				if (strlen(optarg) > 32){
					fprintf(stderr,"Salt is longer than 32chars\n");
					usage(argv[0]);
					break;
				}
				memcpy(salt, optarg, strlen(optarg));
				isSaltSet = true;
				break;
			}
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

	traceanon_port_list_t *currPort = radius_server.port;
	traceanon_port_list_t *tempPort;
	while(currPort != NULL){
		tempPort = currPort;
		currPort = currPort->nextport;
		free(tempPort);
	}

	return exitcode;
}
