/*
 * This file is part of libtrace
 *
 * Copyright (c) 2004 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson 
 *          Perry Lorier 
 *          
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libtrace; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 *
 */


/* @file 
 *
 * @brief Trace file processing library
 *
 * @author Daniel Lawson
 * @author Perry Lorier
 *
 * @internal
 */
#define _GNU_SOURCE
#include "common.h"
#include "config.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#ifdef HAVE_SYS_LIMITS_H
#  include <sys/limits.h>
#endif

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef HAVE_NET_IF_ARP_H
#  include <net/if_arp.h>
#endif

#ifdef HAVE_NET_IF_H
#  include <net/if.h>
#endif

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#ifdef HAVE_NET_ETHERNET_H
#  include <net/ethernet.h>
#endif

#ifdef HAVE_NETINET_IF_ETHER_H
#  include <netinet/if_ether.h>
#endif

#include <time.h>
#include <sys/ioctl.h>

#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#else
#  error "Can't find inttypes.h - this needs to be fixed"
#endif 

#ifdef HAVE_STDDEF_H
#  include <stddef.h>
#else
# error "Can't find stddef.h - do you define ptrdiff_t elsewhere?"
#endif

#include "libtrace.h"
#include "fifo.h"
#include "libtrace_int.h"
#include "parse_cmd.h"

#if HAVE_PCAP_BPF_H
#  include <pcap-bpf.h>
#else
#  ifdef HAVE_NET_BPF_H
#    include <net/bpf.h>
#  endif
#endif

#include "libtrace_int.h"
#include "format_helper.h"
#include <err.h>

#define MAXOPTS 1024

#if HAVE_BPF
/* A type encapsulating a bpf filter
 * This type covers the compiled bpf filter, as well as the original filter
 * string
 *
 */
struct libtrace_filter_t {
	struct bpf_insn *filter;
	char * filterstring;
};
#endif

struct trace_err_t trace_err;

struct libtrace_format_t **format_list = 0;
int format_size = 0;
int nformats = 0;

/* strncpy is not assured to copy the final \0, so we
 * will use our own one that does
 */
static void xstrncpy(char *dest, const char *src, size_t n)
{
        strncpy(dest,src,n);
        dest[n]='\0';
}
 
static char *xstrndup(const char *src,size_t n)
{       
        char *ret=malloc(n+1);
        xstrncpy(ret,src,n);
        return ret;
}

void register_format(struct libtrace_format_t *f) {
	if (format_list == 0) {
		format_size = 10;
		format_list = malloc(
					sizeof(struct libtrace_format_t *) *
					format_size
				);
	} else if (format_size == nformats) {
		format_size = format_size + 10;
		format_list = realloc(format_list,
				sizeof(struct libtrace_format_t *) * 
				format_size);
	}
	format_list[nformats] = f;
	nformats++;
}

/* Prints help information for libtrace 
 *
 * Function prints out some basic help information regarding libtrace,
 * and then prints out the help() function registered with each input module
 */
void trace_help() {
	int i = 0;
	printf("libtrace %s\n",PACKAGE_VERSION);
	for (i = 0; i < nformats; i++) {
		if (format_list[i]->help) {
			format_list[i]->help();
		}
	}
}

/* Prints error information
 *
 * Prints out a descriptive error message for the currently set trace_err value
 */
void trace_perror(const char *caller) {
	switch (trace_err.err_num) {
		case E_BAD_FORMAT:
			fprintf(stderr, "%s: No support for format (%s)\n", caller, trace_err.problem);
			break;
		case E_NO_INIT:
			fprintf(stderr, "%s: Format (%s) does not have an init_trace function defined\n", caller, trace_err.problem);
			break;
		case E_NO_INIT_OUT:
			fprintf(stderr, "%s: Format (%s) does not have an init_output function defined\n", caller, trace_err.problem);
			break;
		case E_URI_LONG:
			fprintf(stderr, "%s: uri is too long\n", caller);
			break;
		case E_URI_NOCOLON:
			fprintf(stderr, "%s: A uri must contain at least one colon e.g. format:destination\n", caller);
			break;
		case E_INIT_FAILED:
			fprintf(stderr, "%s: libtrace failed to initialise (%s)\n",caller,trace_err.problem);
			
		default:
			fprintf(stderr, "Unknown errcode %d\n",trace_err.err_num);
			break;	
	}
	trace_err.err_num = E_NOERROR;
}

#define RP_BUFSIZE 65536
#define URI_PROTO_LINE 16

/* Gets the name of the output format for a given output trace. 
 *
 * @params libtrace	the output trace to get the name of the format for
 * @returns callee-owned null-terminated char* containing the output format
 *
 */
SIMPLE_FUNCTION
char *trace_get_output_format(const struct libtrace_out_t *libtrace) {
	char * format = libtrace->format->name;

	return format;
}

/* Create a trace file from a URI
 *
 * @params char * containing a valid libtrace URI
 * @returns opaque pointer to a libtrace_t
 *
 * Valid URI's are:
 *  erf:/path/to/erf/file
 *  erf:/path/to/erf/file.gz
 *  erf:/path/to/rtclient/socket
 *  erf:-  			(stdin)
 *  dag:/dev/dagcard
 *  pcapint:pcapinterface 		(eg: pcapint:eth0)
 *  pcap:/path/to/pcap/file
 *  pcap:-
 *  rtclient:hostname
 *  rtclient:hostname:port
 *  wag:-
 *  wag:/path/to/wag/file
 *  wag:/path/to/wag/file.gz
 *  wag:/path/to/wag/socket
 *
 * If an error occured when attempting to open a trace, NULL is returned
 * and an error is output to stdout.
 */
struct libtrace_t *trace_create(const char *uri) {
        struct libtrace_t *libtrace = malloc(sizeof(struct libtrace_t));
        char *scan = 0;
        const char *uridata = 0;                  
	int i = 0;
	
	trace_err.err_num = E_NOERROR;
        
        /* parse the URI to determine what sort of event we are dealing with */
	if ((uridata = trace_parse_uri(uri, &scan)) == 0) {
		return 0;
	}
	
	libtrace->event.tdelta = 0.0;

	libtrace->format = 0;
	for (i = 0; i < nformats; i++) {
		if (strlen(scan) == strlen(format_list[i]->name) &&
				strncasecmp(scan,
					format_list[i]->name,
					strlen(scan)) == 0) {
			libtrace->format=format_list[i];
			break;
		}
	}
	if (libtrace->format == 0) {
		trace_err.err_num = E_BAD_FORMAT;
		strcpy(trace_err.problem, scan);
		return 0;
	}

        libtrace->uridata = strdup(uridata);
        /* libtrace->format now contains the type of uri
         * libtrace->uridata contains the appropriate data for this
	 */
        
	if (libtrace->format->init_input) {
		if (!libtrace->format->init_input( libtrace)) {
			trace_err.err_num = E_INIT_FAILED;
			strcpy(trace_err.problem, scan);
			return 0;
		}
	} else {
		trace_err.err_num = E_NO_INIT;
		strcpy(trace_err.problem, scan);
		return 0;
	}
	

        libtrace->fifo = create_tracefifo(1048576);
	assert( libtrace->fifo);
	free(scan);
	libtrace->started=false;
        return libtrace;
}

/* Creates a "dummy" trace file that has only the format type set.
 *
 * @returns opaque pointer to a (sparsely initialised) libtrace_t
 *
 * IMPORTANT: Do not attempt to call trace_read_packet or other such functions with
 * the dummy trace. Its intended purpose is to act as a packet->trace for libtrace_packet_t's
 * that are not associated with a libtrace_t structure.
 */
struct libtrace_t * trace_create_dead (const char *uri) {
	struct libtrace_t *libtrace = malloc(sizeof(struct libtrace_t));
	char *scan = calloc(sizeof(char),URI_PROTO_LINE);
	char *uridata;
	int i;
	
	trace_err.err_num = E_NOERROR;

	if((uridata = strchr(uri,':')) == NULL) {
		xstrncpy(scan, uri, strlen(uri));
	} else {
		xstrncpy(scan,uri, (uridata - uri));
	}
	
	libtrace->format = 0;	
	
	for (i = 0; i < nformats; i++) {
                if (strlen(scan) == strlen(format_list[i]->name) &&
                                !strncasecmp(scan,
                                        format_list[i]->name,
                                        strlen(scan))) {
                                libtrace->format=format_list[i];
                                break;
                                }
        }
        if (libtrace->format == 0) {
                trace_err.err_num = E_BAD_FORMAT;
                strcpy(trace_err.problem, scan);
                return 0;
        }
	
	free(scan);
	return libtrace;

}

/* Creates a trace output file from a URI. 
 *
 * @param uri	the uri string describing the output format and destination
 * @returns opaque pointer to a libtrace_output_t
 * @author Shane Alcock
 *
 * Valid URI's are:
 *  - gzerf:/path/to/erf/file.gz
 *  - gzerf:/path/to/erf/file
 *  - rtserver:hostname
 *  - rtserver:hostname:port
 *
 *  If an error occured when attempting to open the output trace, NULL is returned 
 *  and trace_errno is set. Use trace_perror() to get more information
 */
	
struct libtrace_out_t *trace_create_output(const char *uri) {
	struct libtrace_out_t *libtrace = malloc(sizeof(struct libtrace_out_t));
	
	char *scan = 0;
        const char *uridata = 0;
        int i;

	trace_err.err_num = E_NOERROR;
        /* parse the URI to determine what sort of event we are dealing with */

	if ((uridata = trace_parse_uri(uri, &scan)) == 0) {
		return 0;
	}
	
	
        libtrace->format = 0;
        for (i = 0; i < nformats; i++) {
                if (strlen(scan) == strlen(format_list[i]->name) &&
                                !strncasecmp(scan,
                                        format_list[i]->name,
                                        strlen(scan))) {
                                libtrace->format=format_list[i];
                                break;
                                }
        }
        if (libtrace->format == 0) {
		trace_err.err_num = E_BAD_FORMAT;
		strcpy(trace_err.problem, scan);
                return 0;
        }
        libtrace->uridata = strdup(uridata);


        /* libtrace->format now contains the type of uri
         * libtrace->uridata contains the appropriate data for this
	 */

        if (libtrace->format->init_output) {
                if(!libtrace->format->init_output( libtrace)) {
			return 0;
		}
	} else {
		trace_err.err_num = E_NO_INIT_OUT;
		strcpy(trace_err.problem, scan);
                return 0;
        }


        libtrace->fifo = create_tracefifo(1048576);
        assert( libtrace->fifo);
	free(scan);
	return libtrace;
}

/* Start a trace
 * @param libtrace	the input trace to start
 * @returns 0 on success
 *
 * This does the work associated with actually starting up
 * the trace.  it may fail.
 */
int trace_start(struct libtrace_t *libtrace)
{
	if (libtrace->format->start_input) {
		int ret=libtrace->format->start_input(libtrace);
		if (!ret) {
			return ret;
		}
	}

	libtrace->started=true;
	return 0;
}

/* Parses an output options string and calls the appropriate function to deal with output options.
 *
 * @param libtrace	the output trace object to apply the options to
 * @param options	the options string
 * @returns -1 if option configuration failed, 0 otherwise
 *
 * @author Shane Alcock
 */
int trace_config_output(struct libtrace_out_t *libtrace, 
		trace_option_output_t option,
		void *value) {
	if (libtrace->format->config_output) {
		return libtrace->format->config_output(libtrace, option, value);
	}
	return -1;
}

/* Close a trace file, freeing up any resources it may have been using
 *
 */
void trace_destroy(struct libtrace_t *libtrace) {
        assert(libtrace);
	libtrace->format->fin_input(libtrace);
        /* need to free things! */
        free(libtrace->uridata);
	destroy_tracefifo(libtrace->fifo);
        free(libtrace);
}


void trace_destroy_dead(struct libtrace_t *libtrace) {
	assert(libtrace);
	free(libtrace);
}
/* Close an output trace file, freeing up any resources it may have been using
 *
 * @param libtrace	the output trace file to be destroyed
 *
 * @author Shane Alcock
 * */
void trace_destroy_output(struct libtrace_out_t *libtrace) {
	assert(libtrace);
	libtrace->format->fin_output(libtrace);
	free(libtrace->uridata);
	destroy_tracefifo(libtrace->fifo);
	free(libtrace);
}

libtrace_packet_t *trace_create_packet() {
	libtrace_packet_t *packet = calloc(1,sizeof(libtrace_packet_t));
	/* This used to malloc a packet!  Why do we need to malloc a packet
	 * if we're doing zero copy?
	 */
	return packet;
}

/** Destroy a packet object
 *
 * sideeffect: sets packet to NULL
 */
void trace_destroy_packet(struct libtrace_packet_t **packet) {
	if ((*packet)->buf_control) {
		free((*packet)->buffer);
	}
	free((*packet));
	packet = NULL;
}	

/* Read one packet from the trace into buffer
 *
 * @param libtrace 	the libtrace opaque pointer
 * @param packet  	the packet opaque pointer
 * @returns 0 on EOF, negative value on error
 *
 */
int trace_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {

	assert(libtrace && "You called trace_read_packet() with a NULL libtrace parameter!\n");
	assert(libtrace->started && "BUG: You must call libtrace_start() before trace_read_packet()\n");
	assert(packet);
      
	/* Store the trace we are reading from into the packet opaque 
	 * structure */
	packet->trace = libtrace;

	if (libtrace->format->read_packet) {
		return (packet->size=libtrace->format->read_packet(libtrace,packet));
	}
	packet->size=-1;
	return -1;
}

/* Writes a packet to the specified output
 *
 * @param libtrace	describes the output format, destination, etc.
 * @param packet	the packet to be written out
 * @returns the number of bytes written, -1 if write failed
 *
 * @author Shane Alcock
 * */
int trace_write_packet(struct libtrace_out_t *libtrace, const struct libtrace_packet_t *packet) {
	assert(libtrace);
	assert(packet);	
	/* Verify the packet is valid */
	assert(packet->size<65536);
	assert(packet->size>0);

	if (libtrace->format->write_packet) {
		return libtrace->format->write_packet(libtrace, packet);
	}
	return -1;
}

/* get a pointer to the link layer
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns a pointer to the link layer, or NULL if there is no link layer
 * 
 * @note you should call trace_get_link_type() to find out what type of link layer this is
 */
void *trace_get_link(const struct libtrace_packet_t *packet) {
	return (void *)packet->payload;
}

/*
typedef struct legacy_framing {
	uint64_t 	ts;
	uint32_t	crc;
	uint32_t	header;
	uint32_t	data[12]; // pad to 64 bytes 
} legacy_framing_t;
*/

/* get a pointer to the IP header (if any)
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns a pointer to the IP header, or NULL if there is not an IP packet
 */
struct libtrace_ip *trace_get_ip(const struct libtrace_packet_t *packet) {
        struct libtrace_ip *ipptr = 0;

	switch(trace_get_link_type(packet)) {
		case TRACE_TYPE_80211_PRISM:
			{
				struct ieee_802_11_header *wifi = (char*)trace_get_link(packet)+144;
				if (!wifi) {
					ipptr = NULL;
					break;
				}

				/* Data packet? */
				if (wifi->type != 2) {
					ipptr = NULL;
				}
				else {
					struct ieee_802_11_payload *eth = (void*)wifi->data;
					ipptr = NULL;

					if (ntohs(eth->type) == 0x0800) {
					    ipptr=((void*)eth) + sizeof(*eth);
					} else if (ntohs(eth->type) == 0x8100) {
					    struct libtrace_8021q *vlanhdr =
						(struct libtrace_8021q *)eth;
					    if (ntohs(vlanhdr->vlan_ether_type)
							    == 0x0800) {
						ipptr=((void*)eth) + 
							sizeof(*vlanhdr);
					    }
					}
				}
			}
			break;
		case TRACE_TYPE_80211:
			{ 
				
				struct ieee_802_11_header *wifi = trace_get_link(packet);	
				if (!wifi) {
					ipptr = NULL;
					break;
				}

				/* Data packet? */
				if (wifi->type != 2) {
					ipptr = NULL;
				}
				else {
					struct ieee_802_11_payload *eth = (void*)wifi->data;
					ipptr = NULL;

					if (ntohs(eth->type) == 0x0800) {
					    ipptr=((void*)eth) + sizeof(*eth);
					} else if (ntohs(eth->type) == 0x8100) {
					    struct libtrace_8021q *vlanhdr =
						(struct libtrace_8021q *)eth;
					    if (ntohs(vlanhdr->vlan_ether_type)
							    == 0x0800) {
						ipptr=((void*)eth) + 
							sizeof(*vlanhdr);
					    }
					}
				}
			}
			break;
		case TRACE_TYPE_ETH:
		case TRACE_TYPE_LEGACY_ETH:
			{
				struct libtrace_ether *eth = 
					trace_get_link(packet);
				if (!eth) {
					ipptr = NULL;
					break;
				}
				ipptr = NULL;
				
				if (ntohs(eth->ether_type)==0x0800) {
					ipptr = ((void *)eth) + sizeof(*eth);
				} else if (ntohs(eth->ether_type) == 0x8100) {
					struct libtrace_8021q *vlanhdr = 
						(struct libtrace_8021q *)eth;
					if (ntohs(vlanhdr->vlan_ether_type) 
							== 0x0800) {
						ipptr = ((void *)eth) + 
							sizeof(*vlanhdr);
					}
				}
				break;
			}
		case TRACE_TYPE_NONE:
			ipptr = trace_get_link(packet);
			break;
		case TRACE_TYPE_LINUX_SLL:
			{
				struct trace_sll_header_t *sll;

				sll = trace_get_link(packet);
				if (!sll) {
					ipptr = NULL;
					break;
				}
				if (ntohs(sll->protocol)!=0x0800) {
					ipptr = NULL;
				}
				else {
					ipptr = ((void*)sll)+sizeof(*sll);
				}
			}
			break;
		case TRACE_TYPE_PFLOG:
			{
				struct trace_pflog_header_t *pflog;
				pflog = trace_get_link(packet);
				if (!pflog) {
					ipptr = NULL;
					break;
				}
				if (pflog->af != AF_INET) {
					ipptr = NULL;
				} else {
					ipptr = ((void*)pflog)+sizeof(*pflog);
				}
			}
			break;
		case TRACE_TYPE_LEGACY_POS:
			{
				/* 64 byte capture. */
				struct libtrace_pos *pos = 
					trace_get_link(packet);
				if (ntohs(pos->ether_type) == 0x0800) {
					ipptr = ((void *)pos) + sizeof(*pos);
				} else {
					ipptr = NULL;
				}
				break;
				
			}
		case TRACE_TYPE_LEGACY_ATM:
		case TRACE_TYPE_ATM:
			{
				/* 64 byte capture. */
				struct libtrace_llcsnap *llc = 
					trace_get_link(packet);

				/* advance the llc ptr +4 into the link layer.
				 * need to check what is in these 4 bytes.
				 * don't have time!
				 */
				llc = (void *)llc + 4;
				if (ntohs(llc->type) == 0x0800) {
					ipptr = ((void *)llc) + sizeof(*llc);
				} else {
					ipptr = NULL;
				}
				break;
			}
		default:
			fprintf(stderr,"Don't understand link layer type %i in trace_get_ip()\n",
				trace_get_link_type(packet));
			ipptr=NULL;
			break;
	}

        return ipptr;
}

#define SW_IP_OFFMASK 0xff1f

/* Gets a pointer to the transport layer header (if any)
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns a pointer to the transport layer header, or NULL if there is no header
 */
void *trace_get_transport(const struct libtrace_packet_t *packet) {
        void *trans_ptr = 0;
        struct libtrace_ip *ipptr = 0;

        if (!(ipptr = trace_get_ip(packet))) {
                return 0;
        }

        if ((ipptr->ip_off & SW_IP_OFFMASK) == 0) {
                trans_ptr = (void *)((ptrdiff_t)ipptr + (ipptr->ip_hl * 4));
        }
        return trans_ptr;
}

/* Gets a pointer to the transport layer header (if any) given a pointer to the
 * IP header
 * @param ip		The IP Header
 * @param[out] skipped	An output variable of the number of bytes skipped
 *
 * @returns a pointer to the transport layer header, or NULL if there is no header
 *
 * Skipped can be NULL, in which case it will be ignored
 */
void *trace_get_transport_from_ip(const libtrace_ip_t *ip, int *skipped) {
	void *trans_ptr = 0;	

	if ((ip->ip_off & SW_IP_OFFMASK) == 0) {
		trans_ptr = (void *)((ptrdiff_t)ip + (ip->ip_hl * 4));
	}

	if (skipped)
		*skipped = (ip->ip_hl*4);

	return trans_ptr;
}

/* get a pointer to the TCP header (if any)
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns a pointer to the TCP header, or NULL if there is not a TCP packet
 */
libtrace_tcp_t *trace_get_tcp(const libtrace_packet_t *packet) {
        struct libtrace_tcp *tcpptr = 0;
        struct libtrace_ip *ipptr = 0;

        if(!(ipptr = trace_get_ip(packet))) {
                return 0;
	}
        if (ipptr->ip_p == 6) {
                tcpptr = (struct libtrace_tcp *)trace_get_transport_from_ip(ipptr, 0);
        }
        return tcpptr;
}

/* get a pointer to the TCP header (if any) given a pointer to the IP header
 * @param ip		The IP header
 * @param[out] skipped	An output variable of the number of bytes skipped
 *
 * @returns a pointer to the TCP header, or NULL if this is not a TCP packet
 *
 * Skipped can be NULL, in which case it will be ignored by the program.
 */
libtrace_tcp_t *trace_get_tcp_from_ip(const libtrace_ip_t *ip, int *skipped)
{
	struct libtrace_tcp *tcpptr = 0;

	if (ip->ip_p == 6)  {
		tcpptr = (struct libtrace_tcp *)trace_get_transport_from_ip(ip, skipped);
	}

	return tcpptr;
}

/* get a pointer to the UDP header (if any)
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns a pointer to the UDP header, or NULL if this is not a UDP packet
 */
struct libtrace_udp *trace_get_udp(const struct libtrace_packet_t *packet) {
        struct libtrace_udp *udpptr = 0;
        struct libtrace_ip *ipptr = 0;
        
        if(!(ipptr = trace_get_ip(packet))) {
                return 0;
        }
        if (ipptr->ip_p == 17)  {
                udpptr = (struct libtrace_udp *)trace_get_transport_from_ip(ipptr, 0);
        }

        return udpptr;
}

/* get a pointer to the UDP header (if any) given a pointer to the IP header
 * @param ip		The IP header
 * @param[out] skipped	An output variable of the number of bytes skipped
 *
 * @returns a pointer to the UDP header, or NULL if this is not a UDP packet
 *
 * Skipped can be NULL, in which case it will be ignored by the program.
 */
struct libtrace_udp *trace_get_udp_from_ip(const struct libtrace_ip *ip, int *skipped)
{
	struct libtrace_udp *udpptr = 0;

	if (ip->ip_p == 17) {
		udpptr = (struct libtrace_udp *)trace_get_transport_from_ip(ip, skipped);
	}

	return udpptr;
}


/* get a pointer to the ICMP header (if any)
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns a pointer to the ICMP header, or NULL if this is not a ICMP packet
 */
struct libtrace_icmp *trace_get_icmp(const struct libtrace_packet_t *packet) {
        struct libtrace_icmp *icmpptr = 0;
        struct libtrace_ip *ipptr = 0;
        
        if(!(ipptr = trace_get_ip(packet))) {
                return 0;
        }
        if (ipptr->ip_p == 1){
                icmpptr = (struct libtrace_icmp *)trace_get_transport_from_ip(ipptr, 0);
        }
        return icmpptr;
}

/* get a pointer to the ICMP header (if any) given a pointer to the IP header
 * @param ip		The IP header
 * @param[out] skipped	An output variable of the number of bytes skipped
 *
 * @returns a pointer to the ICMP header, or NULL if this is not a ICMP packet
 *
 * Skipped can be NULL, in which case it will be ignored by the program.
 */
struct libtrace_icmp *trace_get_icmp_from_ip(const struct libtrace_ip *ip, int *skipped)
{
	struct libtrace_icmp *icmpptr = 0;

	if (ip->ip_p == 1)  {
		icmpptr = (struct libtrace_icmp *)trace_get_transport_from_ip(ip, skipped);
	}

	return icmpptr;
}
/* parse an ip or tcp option
 * @param[in,out] ptr	the pointer to the current option
 * @param[in,out] len	the length of the remaining buffer
 * @param[out] type	the type of the option
 * @param[out] optlen 	the length of the option
 * @param[out] data	the data of the option
 *
 * @returns bool true if there is another option (and the fields are filled in)
 *               or false if this was the last option.
 *
 * This updates ptr to point to the next option after this one, and updates
 * len to be the number of bytes remaining in the options area.  Type is updated
 * to be the code of this option, and data points to the data of this option,
 * with optlen saying how many bytes there are.
 *
 * @note Beware of fragmented packets.
 * @author Perry Lorier
 */
int trace_get_next_option(unsigned char **ptr,int *len,
			unsigned char *type,
			unsigned char *optlen,
			unsigned char **data)
{
	if (*len<=0)
		return 0;
	*type=**ptr;
	switch(*type) {
		case 0: /* End of options */
			return 0;
		case 1: /* Pad */
			(*ptr)++;
			(*len)--;
			return 1;
		default:
			*optlen = *(*ptr+1);
			if (*optlen<2)
				return 0; /* I have no idea wtf is going on
					   * with these packets
					   */
			(*len)-=*optlen;
			(*data)=(*ptr+2);
			(*ptr)+=*optlen;
			if (*len<0)
				return 0;
			return 1;
	}
	assert(0);
}


/* Get the current time in DAG time format 
 * @param packet 	a pointer to a libtrace_packet structure
 * @returns a 64 bit timestamp in DAG ERF format (upper 32 bits are the seconds
 * past 1970-01-01, the lower 32bits are partial seconds)
 * @author Daniel Lawson
 */ 
uint64_t trace_get_erf_timestamp(const struct libtrace_packet_t *packet) {
	uint64_t timestamp = 0;
	double seconds = 0.0;
	struct timeval ts;

	assert(packet->size>0 && packet->size<65536);

	if (packet->trace->format->get_erf_timestamp) {
		/* timestamp -> timestamp */
		timestamp = packet->trace->format->get_erf_timestamp(packet);
	} else if (packet->trace->format->get_timeval) {
		/* timeval -> timestamp */
		ts = packet->trace->format->get_timeval(packet);
		timestamp = ((((uint64_t)ts.tv_sec) << 32) + \
				(((uint64_t)ts.tv_usec * UINT_MAX)/1000000));
	} else if (packet->trace->format->get_seconds) {
		/* seconds -> timestamp */
		seconds = packet->trace->format->get_seconds(packet);
		timestamp = ((uint64_t)((uint32_t)seconds) << 32) + \
			    (( seconds - (uint32_t)seconds   ) * UINT_MAX);
	}
	return timestamp;
}

/* Get the current time in struct timeval
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns time that this packet was seen in a struct timeval
 * @author Daniel Lawson
 * @author Perry Lorier
 */ 
struct timeval trace_get_timeval(const struct libtrace_packet_t *packet) {
        struct timeval tv;
	uint64_t ts = 0;
	double seconds = 0.0;
	assert(packet->size>0 && packet->size<65536);
	if (packet->trace->format->get_timeval) {
		/* timeval -> timeval */
		tv = packet->trace->format->get_timeval(packet);
	} else if (packet->trace->format->get_erf_timestamp) {
		/* timestamp -> timeval */
		ts = packet->trace->format->get_erf_timestamp(packet);
#if __BYTE_ORDER == __BIG_ENDIAN
		tv.tv_sec = ts & 0xFFFFFFFF;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
		tv.tv_sec = ts >> 32;
#else
#error "What on earth are you running this on?"
#endif
		ts = (1000000 * (ts & 0xffffffffULL));
       		ts += (ts & 0x80000000ULL) << 1;
       		tv.tv_usec = ts >> 32;
       		if (tv.tv_usec >= 1000000) {
               		tv.tv_usec -= 1000000;
               		tv.tv_sec += 1;
       		}
	} else if (packet->trace->format->get_seconds) {
		/* seconds -> timeval */
		seconds = packet->trace->format->get_seconds(packet);
		tv.tv_sec = (uint32_t)seconds;
		tv.tv_usec = (uint32_t)(((seconds - tv.tv_sec) * 1000000)/UINT_MAX);
	}

        return tv;
}

/* Get the current time in floating point seconds
 * @param packet 	a pointer to a libtrace_packet structure
 * @returns time that this packet was seen in 64bit floating point seconds
 * @author Perry Lorier
 */ 
double trace_get_seconds(const struct libtrace_packet_t *packet) {
	double seconds = 0.0;
	uint64_t ts = 0;
	struct timeval tv;

	assert(packet->size>0 && packet->size<65536);
	
	if (packet->trace->format->get_seconds) {
		/* seconds->seconds */
		seconds = packet->trace->format->get_seconds(packet);
	} else if (packet->trace->format->get_erf_timestamp) {
		/* timestamp -> seconds */
		ts = packet->trace->format->get_erf_timestamp(packet);
		seconds =  (ts>>32) + ((ts & UINT_MAX)*1.0 / UINT_MAX);
	} else if (packet->trace->format->get_timeval) {
		/* timeval -> seconds */
		tv = packet->trace->format->get_timeval(packet);
		seconds = tv.tv_sec + ((tv.tv_usec * UINT_MAX * 1.0)/1000000);
	}

	return seconds;
}

/* Get the size of the packet in the trace
 * @param packet 	the packet opaque pointer
 * @returns the size of the packet in the trace
 * @author Perry Lorier
 * @note The return size refers to the network-level payload of the packet and
 * does not include any capture headers. For example, an Ethernet packet with
 * an empty TCP packet will return sizeof(ethernet_header) + sizeof(ip_header)
 * + sizeof(tcp_header).
 * @note Due to this being a header capture, or anonymisation, this may not
 * be the same size as the original packet.  See trace_get_wire_length() for the 
 * original size of the packet.
 * @note This can (and often is) different for different packets in a trace!
 * @note This is sometimes called the "snaplen".
 */ 
int trace_get_capture_length(const struct libtrace_packet_t *packet) {

	assert(packet->size>0 && packet->size<65536);

	if (packet->trace->format->get_capture_length) {
		return packet->trace->format->get_capture_length(packet);
	}
	return -1;
}
	
/* Get the size of the packet as it was seen on the wire.
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns the size of the packet as it was on the wire.
 * @author Perry Lorier
 * @author Daniel Lawson
 * @note Due to the trace being a header capture, or anonymisation this may
 * not be the same as the Capture Len.
 */ 
int trace_get_wire_length(const struct libtrace_packet_t *packet){
	assert(packet->size>0 && packet->size<65536);

	if (packet->trace->format->get_wire_length) {
		return packet->trace->format->get_wire_length(packet);
	}
	return -1;

}

/* Get the length of the capture framing headers.
 * @param packet  	the packet opaque pointer
 * @returns the size of the packet as it was on the wire.
 * @author Perry Lorier
 * @author Daniel Lawson
 * @note this length corresponds to the difference between the size of a 
 * captured packet in memory, and the captured length of the packet
 */ 
SIMPLE_FUNCTION
int trace_get_framing_length(const struct libtrace_packet_t *packet) {
	if (packet->trace->format->get_framing_length) {
		return packet->trace->format->get_framing_length(packet);
	}
	return -1;
}


/* Get the type of the link layer
 * @param packet 	a pointer to a libtrace_packet structure
 * @returns libtrace_linktype_t
 * @author Perry Lorier
 * @author Daniel Lawson
 */
libtrace_linktype_t trace_get_link_type(const struct libtrace_packet_t *packet ) {
	if (packet->trace->format->get_link_type) {
		return packet->trace->format->get_link_type(packet);
	}
	return -1;
}

/* Get the source MAC addres
 * @param packet 	a pointer to a libtrace_packet structure
 * @returns a pointer to the source mac, (or NULL if there is no source MAC)
 * @author Perry Lorier
 */
uint8_t *trace_get_source_mac(const struct libtrace_packet_t *packet) {
	void *link = trace_get_link(packet);
	struct ieee_802_11_header *wifi = link;
        struct libtrace_ether *ethptr = link;
	if (!link)
		return NULL;
	switch (trace_get_link_type(packet)) {
		case TRACE_TYPE_80211:
			return (uint8_t*)&wifi->mac2;
		case TRACE_TYPE_ETH:
			return (uint8_t*)&ethptr->ether_shost;
		default:
			fprintf(stderr,"Not implemented\n");
			assert(0);
	}
}

/* Get the destination MAC addres
 * @param packet a libtrace_packet pointer
 * @returns a pointer to the destination mac, (or NULL if there is no 
 * destination MAC)
 * @author Perry Lorier
 */
uint8_t *trace_get_destination_mac(const struct libtrace_packet_t *packet) {
	void *link = trace_get_link(packet);
	struct ieee_802_11_header *wifi = link;
        struct libtrace_ether *ethptr = link;
	if (!link)
		return NULL;
	switch (trace_get_link_type(packet)) {
		case TRACE_TYPE_80211:
			return (uint8_t*)&wifi->mac1;
		case TRACE_TYPE_ETH:
			return (uint8_t*)&ethptr->ether_dhost;
		default:
			fprintf(stderr,"Not implemented\n");
			assert(0);
	}
}


/* process a libtrace event
 * @param trace the libtrace opaque pointer
 * @param packet the libtrace_packet opaque pointer
 * @returns
 *  TRACE_EVENT_IOWAIT	Waiting on I/O on fd
 *  TRACE_EVENT_SLEEP	Next event in seconds
 *  TRACE_EVENT_PACKET	Packet arrived in buffer with size size
 *  TRACE_EVENT_TERMINATE Trace terminated (perhaps with an error condition)
 * FIXME currently keeps a copy of the packet inside the trace pointer,
 * which in turn is stored inside the new packet object...
 * @author Perry Lorier
 */
struct libtrace_eventobj_t trace_event(struct libtrace_t *trace, 
		struct libtrace_packet_t *packet) {
	struct libtrace_eventobj_t event = {0,0,0.0,0};

	if (!trace) {
		fprintf(stderr,"You called trace_event() with a NULL trace object!\n");
	}
	assert(trace);
	assert(packet);

	/* Store the trace we are reading from into the packet opaque
	 * structure */
	packet->trace = trace;

	if (packet->trace->format->trace_event) {
		return packet->trace->format->trace_event(trace,packet);
	} else {
		return event;
	}

}

/* setup a BPF filter
 * @param filterstring a char * containing the bpf filter string
 * @returns opaque pointer pointer to a libtrace_filter_t object
 * @author Daniel Lawson
 */
struct libtrace_filter_t *trace_bpf_setfilter(const char *filterstring) {
#if HAVE_BPF
	struct libtrace_filter_t *filter = malloc(sizeof(struct libtrace_filter_t));
	filter->filterstring = strdup(filterstring);
	filter->filter = 0;
	return filter;
#else
	fprintf(stderr,"This version of libtrace does not have bpf filter support\n");
	return 0;
#endif
}

/* apply a BPF filter
 * @param filter the filter opaque pointer
 * @param packet the packet opaque pointer
 * @returns 0 if the filter fails, 1 if it succeeds
 * @author Daniel Lawson
 */
int trace_bpf_filter(struct libtrace_filter_t *filter,
			const struct libtrace_packet_t *packet) {
#if HAVE_BPF
	void *linkptr = 0;
	int clen = 0;
	assert(filter);
	assert(packet);
	linkptr = trace_get_link(packet);
	if (!linkptr) {
		return 0;
	}
	
	clen = trace_get_capture_length(packet);
	

	if (filter->filterstring && ! filter->filter) {
		pcap_t *pcap;
		struct bpf_program bpfprog;
		pcap=(pcap_t *)pcap_open_dead(
				libtrace_to_pcap_dlt(trace_get_link_type(packet)),
				1500);
		/* build filter */
		if (pcap_compile( pcap, &bpfprog, filter->filterstring, 1, 0)) {
			printf("bpf compilation error: %s: %s\n", 
				pcap_geterr(pcap),filter->filterstring);
			assert(0);
		}
		pcap_close(pcap);
		filter->filter = bpfprog.bf_insns;	
	}

	assert(filter->filter);
	return bpf_filter(filter->filter, linkptr, clen, clen);
#else
	fprintf(stderr,"This version of libtrace does not have bpf filter support\n");
	return 0;
#endif
}

/* Set the direction flag, if it has one
 * @param packet the packet opaque pointer
 * @param direction the new direction (0,1,2,3)
 * @returns a signed value containing the direction flag, or -1 if this is not supported
 * @author Daniel Lawson
 */
int8_t trace_set_direction(struct libtrace_packet_t *packet, int8_t direction) {
	assert(packet);
	assert(packet->size>0 && packet->size<65536);
	if (packet->trace->format->set_direction) {
		return packet->trace->format->set_direction(packet,direction);
	}
	return -1;
}

/* Get the direction flag, if it has one
 * @param packet a pointer to a libtrace_packet structure
 * @returns a signed value containing the direction flag, or -1 if this is not supported
 * The direction is defined as 0 for packets originating locally (ie, outbound)
 * and 1 for packets originating remotely (ie, inbound).
 * Other values are possible, which might be overloaded to mean special things
 * for a special trace.
 * @author Daniel Lawson
 */
int8_t trace_get_direction(const struct libtrace_packet_t *packet) {
	assert(packet);
	assert(packet->size>0 && packet->size<65536);
	if (packet->trace->format->get_direction) {
		return packet->trace->format->get_direction(packet);
	}
	return -1;
}

struct ports_t {
	uint16_t src;
	uint16_t dst;
};

/* Return the client port
 */
uint16_t trace_get_source_port(const struct libtrace_packet_t *packet)
{
	struct libtrace_ip *ip = trace_get_ip(packet);
	struct ports_t *port;
	if (6 != ip->ip_p
	  && 17 != ip->ip_p)
		return 0;
	if (0 != (ip->ip_off & SW_IP_OFFMASK))
		return 0;

	port = (struct ports_t *)((ptrdiff_t)ip + (ip->ip_hl * 4));

	return ntohs(port->src);
}

/* Same as get_source_port except use the destination port */
uint16_t trace_get_destination_port(const struct libtrace_packet_t *packet)
{
	struct libtrace_ip *ip = trace_get_ip(packet);
	struct ports_t *port;

	if (6 != ip->ip_p
	  && 17 != ip->ip_p)
		return 0;

	if (0 != (ip->ip_off & SW_IP_OFFMASK))
		return 0;

	port = (struct ports_t *)((ptrdiff_t)ip + (ip->ip_hl * 4));

	return ntohs(port->dst);
}

#define ROOT_SERVER(x) ((x) < 512)
#define ROOT_CLIENT(x) ((512 <= (x)) && ((x) < 1024))
#define NONROOT_SERVER(x) ((x) >= 5000)
#define NONROOT_CLIENT(x) ((1024 <= (x)) && ((x) < 5000))
#define DYNAMIC(x) ((49152 < (x)) && ((x) < 65535))
#define SERVER(x) ROOT_SERVER(x) || NONROOT_SERVER(x)
#define CLIENT(x) ROOT_CLIENT(x) || NONROOT_CLIENT(x) 

/* Attempt to deduce the 'server' port
 * @param protocol the IP protocol (eg, 6 or 17 for TCP or UDP)
 * @param source the TCP or UDP source port
 * @param dest the TCP or UDP destination port
 * @returns a hint as to which port is the server port
 * @author Daniel Lawson
 */
int8_t trace_get_server_port(uint8_t protocol __attribute__((unused)), uint16_t source, uint16_t dest) {
	/*
	 * * If the ports are equal, return DEST
	 * * Check for well-known ports in the given protocol
	 * * Root server ports: 0 - 511
	 * * Root client ports: 512 - 1023
	 * * non-root client ports: 1024 - 4999
	 * * non-root server ports: 5000+
	 * * Check for static ranges: 1024 - 49151
	 * * Check for dynamic ranges: 49152 - 65535
	 * * flip a coin.
	 */
	
	/* equal */
	if (source == dest)
		return USE_DEST;

	/* root server port, 0 - 511 */
	if (ROOT_SERVER(source) && ROOT_SERVER(dest)) {
		if (source < dest)
			return USE_SOURCE;
		return USE_DEST;
	}

	if (ROOT_SERVER(source) && !ROOT_SERVER(dest))
		return USE_SOURCE;
	if (!ROOT_SERVER(source) && ROOT_SERVER(dest))
		return USE_DEST;

	/* non-root server */
	if (NONROOT_SERVER(source) && NONROOT_SERVER(dest)) {
		if (source < dest)
			return USE_SOURCE;
		return USE_DEST;
	}
	if (NONROOT_SERVER(source) && !NONROOT_SERVER(dest))
		return USE_SOURCE;
	if (!NONROOT_SERVER(source) && NONROOT_SERVER(dest))
		return USE_DEST;

	/* root client */
	if (ROOT_CLIENT(source) && ROOT_CLIENT(dest)) {
		if (source < dest)
			return USE_SOURCE;
		return USE_DEST;
	}
	if (ROOT_CLIENT(source) && !ROOT_CLIENT(dest)) {
		/* prefer root-client over nonroot-client */
		if (NONROOT_CLIENT(dest))
			return USE_SOURCE;
		return USE_DEST;
	}
	if (!ROOT_CLIENT(source) && ROOT_CLIENT(dest)) {
		/* prefer root-client over nonroot-client */
		if (NONROOT_CLIENT(source))
			return USE_DEST;
		return USE_SOURCE;
	}
	
	/* nonroot client */
	if (NONROOT_CLIENT(source) && NONROOT_CLIENT(dest)) {
		if (source < dest) 
			return USE_SOURCE;
		return USE_DEST;
	}
	if (NONROOT_CLIENT(source) && !NONROOT_CLIENT(dest))
		return USE_DEST;
	if (!NONROOT_CLIENT(source) && NONROOT_CLIENT(dest))
		return USE_SOURCE;

	/* dynamic range */
	if (DYNAMIC(source) && DYNAMIC(dest))
		if (source < dest)
			return USE_SOURCE;
		return USE_DEST;
	if (DYNAMIC(source) && !DYNAMIC(dest))
		return USE_DEST;
	if (!DYNAMIC(source) && DYNAMIC(dest))
		return USE_SOURCE;
	/*
	if (SERVER(source) && CLIENT(dest)) 
		return USE_SOURCE;
	
	if (SERVER(dest) && CLIENT(source)) 
		return USE_DEST;
	if (ROOT_SERVER(source) && !ROOT_SERVER(dest)) 
		return USE_SOURCE;
	if (ROOT_SERVER(dest) && !ROOT_SERVER(source)) 
		return USE_DEST;
	*/
	/* failing that test... */
	if (source < dest) {
		return USE_SOURCE;
	} 
	return USE_DEST;
	
}

/* Truncate the packet at the suggested length
 * @param packet	the packet opaque pointer
 * @param size		the new length of the packet
 * @returns the new size of the packet
 * @note size and the return size refer to the network-level payload of the
 * packet, and do not include any capture headers. For example, to truncate a
 * packet after the IP header, set size to sizeof(ethernet_header) +
 * sizeof(ip_header)
 * @note If the original network-level payload is smaller than size, then the
 * original size is returned and the packet is left unchanged.
 * @author Daniel Lawson
 */
size_t trace_set_capture_length(struct libtrace_packet_t *packet, size_t size) {
	assert(packet);
	assert(packet->size>0 && packet->size<65536);

	if (packet->trace->format->set_capture_length) {
		return packet->trace->format->set_capture_length(packet,size);
	}

	return -1;
}

const char * trace_parse_uri(const char *uri, char **format) {
	const char *uridata = 0;
	
	if((uridata = strchr(uri,':')) == NULL) {
                /* badly formed URI - needs a : */
                trace_err.err_num = E_URI_NOCOLON;
                return 0;
        }

        if ((uridata - uri) > URI_PROTO_LINE) {
                /* badly formed URI - uri type is too long */
                trace_err.err_num = E_URI_LONG;
                return 0;
        }

        *format=xstrndup(uri, (uridata - uri));

	/* push uridata past the delimiter */
        uridata++;
	
	return uridata;
}
	
