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


/** @file 
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
#include "format.h"
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

#if HAVE_PCAP_BPF_H
#  include <pcap-bpf.h>
#else
#  ifdef HAVE_NET_BPF_H
#    include <net/bpf.h>
#  endif
#endif

#if HAVE_PCAP_H
#  include <pcap.h>
#  ifdef HAVE_PCAP_INT_H
#    include <pcap-int.h>
#  endif
#endif 

#ifdef HAVE_ZLIB_H
#  include <zlib.h>
#endif


#include "wag.h"

#ifdef HAVE_DAG_API
#  include "dagnew.h"
#  include "dagapi.h"
#else
#  include "dagformat.h"
#endif

#include "format.h"
//#include "format/format_list.h"
#include <err.h>

//typedef enum {SOCKET, TRACE, STDIN, DEVICE, INTERFACE, RT } source_t;

//typedef enum {ERF, PCAP, PCAPINT, DAG, RTCLIENT, WAG, WAGINT } format_e_t;

typedef enum {RTSERVER, GZERF } output_t;
#if HAVE_BPF
/** A type encapsulating a bpf filter
 * This type covers the compiled bpf filter, as well as the original filter
 * string
 *
 */
struct libtrace_filter_t {
	struct bpf_insn *filter;
	char * filterstring;
};
#endif

struct libtrace_out_t {
	output_t outputformat;

	union {
		struct {
			char *hostname;
			short port;
		} rt;
		char *path;
		char *interface;
	} conn_info;

        union {
                int fd;
#if HAVE_ZLIB
                gzFile *file;
#else
                FILE *file;
#endif
#if HAVE_PCAP
                pcap_t *pcap;
#endif
        } output;

	struct fifo_t *fifo;
};



struct format_t **format_list = 0;
int format_size = 0;
int nformats = 0;

void register_format(struct format_t *f) {
	fprintf(stderr,"Registering input format %s\n",f->name);
	if (format_list == 0) {
		format_size = 10;
		format_list = malloc(sizeof(struct format_t *) * format_size);
	} else if (format_size == nformats) {
		format_size = format_size + 10;
		format_list = realloc(format_list,
				sizeof(struct format_t *) * format_size);
	}
	format_list[nformats] = f;
	nformats++;
}


#define RP_BUFSIZE 65536

#define URI_PROTO_LINE 16
static int init_trace(struct libtrace_t **libtrace, char *uri) {
        char *scan = calloc(sizeof(char),URI_PROTO_LINE);
        char *uridata = 0;                  
	int i = 0;
	struct stat buf;
        
        // parse the URI to determine what sort of event we are dealing with
       
        // want snippet before the : to get the uri base type.

        if((uridata = strchr(uri,':')) == NULL) {
                // badly formed URI - needs a :
                return 0;
        }

        if ((*uridata - *uri) > URI_PROTO_LINE) {
                // badly formed URI - uri type is too long
                return 0;
        }
        strncpy(scan,uri, (uridata - uri));

	(*libtrace)->tdelta = 0.0;


	(*libtrace)->format = 0;
	for (i = 0; i < nformats; i++) {
		if (strlen(scan) == strlen(format_list[i]->name) &&
				!strncasecmp(scan,
					format_list[i]->name,
					strlen(scan))) {
				(*libtrace)->format=format_list[i];
				break;
				}
	}
	if ((*libtrace)->format == 0) {
		fprintf(stderr,
			"libtrace has no support for this format (%s)\n",scan);
		return 0;
	}

        // push uridata past the delimiter
        uridata++;
        (*libtrace)->conn_info.path = strdup(uridata);

        // libtrace->format now contains the type of uri
        // libtrace->uridata contains the appropriate data for this
        
	if ((*libtrace)->format->init_input) {
		(*libtrace)->format->init_input( (*libtrace));
	} else {
		fprintf(stderr,
			"No init function for format %s\n",scan);
		return 0;
	}
	

        (*libtrace)->fifo = create_fifo(1048576);
	assert( (*libtrace)->fifo);
	//(*libtrace)->packet.buffer = 0;
	//(*libtrace)->packet.size = 0;

        return 1;
}

/** Initialises the data contained within the libtrace_out_t structure, based on the provided uri.
 *
 * @param libtrace	the libtrace_out_t structure to initialise
 * @param uri		the uri defining the output type and destination
 * @returns		1 if initialised successfully, 0 otherwise
 *
 * @author Shane Alcock
 * */
static int init_output(struct libtrace_out_t **libtrace, char *uri) {
        char *scan = calloc(sizeof(char),URI_PROTO_LINE);
        char *uridata = 0;

        // parse the URI to determine what sort of event we are dealing with

        // want snippet before the : to get the uri base type.

        if((uridata = strchr(uri,':')) == NULL) {
                // badly formed URI - needs a :
                return 0;
        }

        if ((*uridata - *uri) > URI_PROTO_LINE) {
                // badly formed URI - uri type is too long
                return 0;
        }
        strncpy(scan,uri, (uridata - uri));

        if (!strncasecmp(scan,"gzerf",5)) {
		(*libtrace)->outputformat = GZERF;
	} else if (!strncasecmp(scan, "rt", 2)) {
		(*libtrace)->outputformat = RTSERVER;
	} else {
		return 0;
	}

	uridata ++;
	switch((*libtrace)->outputformat) {
		case GZERF:
			/* 
			 * Acceptable uridata takes the form:
			 * /path/to/file.gz
			 */
			(*libtrace)->conn_info.path = strdup(uridata);
			break;
		case RTSERVER:
			/* 
			 * Possible uridata formats:
			 * hostname
			 * hostname:port
			 */
			if (strlen(uridata) == 0) {
                                (*libtrace)->conn_info.rt.hostname =
                                        strdup("localhost");
                                (*libtrace)->conn_info.rt.port =
                                        COLLECTOR_PORT;
                                break;
                        }
                        if ((scan = strchr(uridata,':')) == NULL) {
                                (*libtrace)->conn_info.rt.hostname =
                                        strdup(uridata);
                                (*libtrace)->conn_info.rt.port =
                                        COLLECTOR_PORT;
                        } else {
                                (*libtrace)->conn_info.rt.hostname =
                                        (char *)strndup(uridata,(scan - uridata));

                                (*libtrace)->conn_info.rt.port =
                                        atoi(++scan);
                        }
                        break;
		default:
			fprintf(stderr, "How did you get here??\n");
	}
	(*libtrace)->fifo = create_fifo(1048576);
	assert( (*libtrace)->fifo);
	return 1;
} 

/** Create a trace file from a URI
 * 
 * @returns opaque pointer to a libtrace_t
 *
 * Valid URI's are:
 *  erf:/path/to/erf/file
 *  erf:/path/to/erf/file.gz
 *  erf:/path/to/rtclient/socket
 *  erf:-  			(stdin)
 *  pcapint:pcapinterface 		(eg: pcapint:eth0)
 *  pcap:/path/to/pcap/file
 *  pcap:-
 *  rtclient:hostname
 *  rtclient:hostname:port
 *  wag:-
 *  wag:/path/to/wag/file
 *  wag:/path/to/wag/file.gz
 *  wag:/path/to/wag/socket
 *  wagint:/dev/device
 *
 * URIs which have yet to be implemented are:
 * dag:/dev/dagcard
 * pcap:/path/to/pcap/socket
 *
 * If an error occured when attempting to open a trace, NULL is returned
 * and an error is output to stdout.
 */
struct libtrace_t *trace_create(char *uri) {
        struct libtrace_t *libtrace = malloc(sizeof(struct libtrace_t));
        struct hostent *he;
        struct sockaddr_in remote;
        struct sockaddr_un unix_sock;
#if HAVE_PCAP
        char errbuf[PCAP_ERRBUF_SIZE];
#endif

        if(init_trace(&libtrace,uri) == 0) {
                return 0;
        }
       
        return libtrace;
}

/** Creates a libtrace_out_t structure and the socket / file through which output will be directed.
 *
 * @param uri	the uri string describing the output format and the destination
 * @returns the newly created libtrace_out_t structure
 * 
 * @author Shane Alcock
 * */
struct libtrace_out_t *trace_output_create(char *uri) {
	struct libtrace_out_t *libtrace = malloc(sizeof(struct libtrace_out_t));
	struct sockaddr_in remote, client;
	int client_fd, clilen;
	struct hostent *he;
	
	if (init_output(&libtrace, uri) == 0)
		return 0;

	switch(libtrace->outputformat) {
		case RTSERVER:
                        if ((he=gethostbyname(libtrace->conn_info.rt.hostname)) == NULL) {
                                perror("gethostbyname");
                                return 0;
                        }
                        if ((libtrace->output.fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                                perror("socket");
                                return 0;
                        }
			// Need to set up a listening server here
			bzero((char *) &remote, sizeof(remote)); 
			remote.sin_family = AF_INET;
			remote.sin_addr.s_addr = INADDR_ANY;
			remote.sin_port = htons(libtrace->conn_info.rt.port);

			if (bind(libtrace->output.fd, (struct sockaddr *) &remote, sizeof(remote)) < 0) {
				perror("bind");
				return 0;
			}
                       	fprintf(stderr, "Waiting for client to connect\n");

			listen(libtrace->output.fd, 5);
			clilen = sizeof(client);
			if ((client_fd = accept(libtrace->output.fd, (struct sockaddr *) &client, &clilen)) < 0) {
				perror("accept");
				return 0;
			}
			libtrace->output.fd = client_fd;
			fprintf(stderr, "Client connected\n");                       
			break;


		case GZERF:
/* Catch undefined O_LARGEFILE on *BSD etc */
#ifndef O_LARGEFILE
#  define O_LARGEFILE 0
#endif

#if HAVE_ZLIB
                        // using gzdopen means we can set O_LARGEFILE
                        // ourselves. However, this way is messy and
                        // we lose any error checking on "open"
			libtrace->output.file = gzdopen(open(libtrace->conn_info.path, O_CREAT | O_LARGEFILE | O_WRONLY, S_IRUSR | S_IWUSR), "w");
#else
	               	libtrace->output.file = fdopen(open(libtrace->conn_info.path,O_CREAT | O_LARGEFILE | O_WRONLY, S_IRUSR | S_IWUSR), "w");
#endif			
			if (!libtrace->output.file) {
				perror("gzdopen (or fdopen)");
				return 0;
			}
			break;
		default:
			fprintf(stderr, "Unrecognised output type - failure to create output instance \n");
			exit(0);
	}
	return libtrace;
}

/** Close a trace file, freeing up any resources it may have been using
 *
 */
void trace_destroy(struct libtrace_t *libtrace) {
        assert(libtrace);
	libtrace->format->fin_input(libtrace);
        // need to free things!
        destroy_fifo(libtrace->fifo);
        free(libtrace);
}

/** Close an output trace file, freeing up any resources it may have been using
 *
 * @param libtrace	the output trace file to be destroyed
 *
 * @author Shane Alcock
 * */
void trace_output_destroy(struct libtrace_out_t *libtrace) {
	assert(libtrace);

	if (libtrace->outputformat == RTSERVER) {
		close(libtrace->output.fd);
	}
	else {
#if HAVE_ZLIB
                gzclose(libtrace->output.file);
#else
                fclose(libtrace->output.file);
#endif
	}
	destroy_fifo(libtrace->fifo);
	free(libtrace);
}

static int trace_read(struct libtrace_t *libtrace, void *buffer, size_t len) {
        int numbytes;
        static short lctr = 0;
	struct dag_record_t *recptr = 0;
        int rlen;
	assert(libtrace);
        assert(len >= 0);

        if (buffer == 0)
                buffer = malloc(len);

	while(1) {
		switch(libtrace->sourcetype) {
			case SOCKET:
			case RT:

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
				// read from the network
				if ((numbytes=recv(libtrace->input.fd, 
								buffer, 
								len, 
								MSG_NOSIGNAL)) == -1) {
					if (errno == EINTR) {
						// ignore EINTR in case 
						// a caller is using signals
						continue;
					}
					perror("recv");
					return -1;
				}
				break;
			case DEVICE:
				if (libtrace->format->read) {
					libtrace->format->read(libtrace,buffer,len);
				} else {
					if ((numbytes=read(libtrace->input.fd, 
								buffer, 
								len)) == -1) {
						perror("read");
						return -1;
					}
				}
				break;
			default:
#if HAVE_ZLIB
				if ((numbytes=gzread(libtrace->input.file,
								buffer,
								len)) == -1) {
					perror("gzread");
					return -1;
				}
#else
				if ((numbytes=fread(buffer,len,1,libtrace->input.file)) == 0 ) {
					if(feof(libtrace->input.file)) {
						return 0;
					}
					if(ferror(libtrace->input.file)) {
						perror("fread");
						return -1;
					}
					return 0;
				}
#endif
		}
		break;
	}
        return numbytes;

}

#if HAVE_PCAP
void trace_pcap_handler(u_char *user, const struct pcap_pkthdr *pcaphdr, const u_char *pcappkt) {
	struct libtrace_packet_t *packet = (struct libtrace_packet_t *)user;	
	void *buffer = packet->buffer;
	int numbytes = 0;
	
	memcpy(buffer,pcaphdr,sizeof(struct pcap_pkthdr));
	numbytes = pcaphdr->len;
	memcpy(buffer + sizeof(struct pcap_pkthdr),pcappkt,numbytes);

	packet->size = numbytes + sizeof(struct pcap_pkthdr);

}
#endif
/** Read one packet from the trace into buffer
 *
 * @param libtrace 	the libtrace opaque pointer
 * @param packet  	the packet opaque pointer
 * @returns false if it failed to read a packet
 *
 */
int trace_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {

	if (!libtrace) {
		fprintf(stderr,"Oi! You called trace_read_packet() with a NULL libtrace parameter!\n");
	}
        assert(libtrace);
        assert(packet);
      
	/* Store the trace we are reading from into the packet opaque 
	 * structure */
	packet->trace = libtrace;

	if (libtrace->format->read_packet) {
		return libtrace->format->read_packet(libtrace,packet);
	}
}

static int trace_write(struct libtrace_out_t *libtrace, void *buffer, size_t len) {
	int numbytes = 0;

	assert(libtrace);
	assert(len >= 0);

	if (buffer == NULL) {
		return 0;
	}

	while (1) {
		switch(libtrace->outputformat) {
			case RTSERVER:
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
				// Write to the network
				if ((numbytes = send(libtrace->output.fd, 
							buffer,
							len,
							MSG_NOSIGNAL)) == -1) {
					if (errno == EINTR) {
						continue;
					}
					perror("send");
					return -1;
				}
				break;
			case GZERF:			
#if HAVE_ZLIB
				if ((numbytes = gzwrite(libtrace->output.file,
							buffer,
							len)) == -1) {
					perror("gzwrite");
					return -1;
				}
				break;
#else
				// Do binary write instead
				if ((numbytes = fwrite(buffer, len, 1, libtrace->output.file)) == 0) {
					perror("fwrite");
					return -1;
				}
				break;
#endif
			default:
				fprintf(stderr, "Bad output type\n");
				break;
		}
		break;
	}	
	return numbytes;
}		

/** Writes a packet to the specified output
 *
 * @param libtrace	describes the output format, destination, etc.
 * @param packet	the packet to be written out
 * @returns the number of bytes written, -1 if write failed
 *
 * @author Shane Alcock
 * */
int trace_write_packet(struct libtrace_out_t *libtrace, struct libtrace_packet_t *packet) {
	// initialise stuff
	int numbytes, size;
	char buf[RP_BUFSIZE];
	int intsize = sizeof(int);
	void *buffer = &buf[intsize];
	int write_required = 0;

	assert(libtrace);
	assert(packet);	

	if (libtrace->outputformat == GZERF) {
		// do gzwrite
		if ((numbytes = gzwrite(libtrace->output.file, packet->buffer, packet->size)) == 0) {
			perror("gzwrite");
			return -1;
		}
		return numbytes;
	}
	
	// do fifo stuff for RT output instead
	if (libtrace->outputformat == RTSERVER) {
		do {
			assert(libtrace->fifo);

			if (fifo_out_available(libtrace->fifo) == 0 || write_required) {
				// Packet added to fifo
				if ((numbytes = fifo_write(libtrace->fifo, packet->buffer, packet->size)) == 0) {
					// some error with the fifo
					perror("fifo_write");
					return -1;
				}
				write_required = 0;
			}
			
			// Read from fifo and add protocol header
			if ((numbytes = fifo_out_read(libtrace->fifo, buffer, sizeof(dag_record_t))) == 0) {
				// failure reading in from fifo
				fifo_out_reset(libtrace->fifo);
				write_required = 1;
				continue;
			}
			size = ntohs(((dag_record_t *)buffer)->rlen);		
			assert(size < LIBTRACE_PACKET_BUFSIZE);
	
			if ((numbytes = fifo_out_read(libtrace->fifo, buffer, size)) == 0) {
				// failure reading in from fifo
				fifo_out_reset(libtrace->fifo);
				write_required = 1;
				continue;
			}
			fifo_out_update(libtrace->fifo, size);	
			// Sort out the protocol header
			memcpy(buf, &packet->status, intsize);
						

			// Send the buffer out on the wire
			if ((numbytes = trace_write(libtrace, buf, size + sizeof(int))) <=0 ) {
				return numbytes;
			}

			// Need an ack to come back
			// TODO: Obviously this is a little unfinished
			if ("ACK_ARRIVES") {
				fifo_ack_update(libtrace->fifo, size);
				return numbytes;
			} else {
				fifo_out_reset(libtrace->fifo);
			}
		} while(1);
	}

	// Unacceptable output format
	fprintf(stderr, "Unknown Output format \n");
	assert(0);
}

/** get a pointer to the link layer
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns a pointer to the link layer, or NULL if there is no link layer
 * you should call trace_get_link_type() to find out what type of link layer this is
 */
void *trace_get_link(const struct libtrace_packet_t *packet) {
        const void *ethptr = 0;
	
      	if (packet->trace->format->get_link) {
		ethptr = packet->trace->format->get_link(packet);
	}
        return (void *)ethptr;
}

/** get a pointer to the IP header (if any)
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns a pointer to the IP header, or NULL if there is not an IP packet
 */
struct libtrace_ip *trace_get_ip(const struct libtrace_packet_t *packet) {
        struct libtrace_ip *ipptr = 0;

	switch(trace_get_link_type(packet)) {
		case TRACE_TYPE_80211:
			{ 
				
				struct ieee_802_11_header *wifi = trace_get_link(packet);	
				if (!wifi) {
					ipptr = NULL;
					break;
				}

				// Data packet?
				if (wifi->type != 2) {
					ipptr = NULL;
				}
				else {
					struct ieee_802_11_payload *eth = (void*)wifi->data;
					if (eth->type != 0x0008) {
						ipptr=NULL;
					} else {
						ipptr=(void*)eth->data;
					}
				}
			}
			break;
		case TRACE_TYPE_ETH:
			{
				struct ether_header *eth = 
					trace_get_link(packet);
				if (!eth) {
					ipptr = NULL;
					break;
				}
				if (ntohs(eth->ether_type)!=0x0800) {
					ipptr = NULL;
				}
				else {
					ipptr = ((void *)eth) + 14;
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
		case TRACE_TYPE_ATM:
			{
				struct atm_rec *atm = 
					trace_get_link(packet);
				// TODO: Find out what ATM does, and return
				//       NULL for non IP data
				//       Presumably it uses the normal stuff
				if (!atm) {
					ipptr = NULL;
					break;
				}
				ipptr =  (void*)&atm->pload;
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

/** get a pointer to the TCP header (if any)
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns a pointer to the TCP header, or NULL if there is not a TCP packet
 */
struct libtrace_tcp *trace_get_tcp(const struct libtrace_packet_t *packet) {
        struct libtrace_tcp *tcpptr = 0;
        struct libtrace_ip *ipptr = 0;

        if(!(ipptr = trace_get_ip(packet))) {
                return 0;
	}
        if ((ipptr->ip_p == 6) && ((ipptr->ip_off & SW_IP_OFFMASK) == 0))  {
                tcpptr = (struct libtrace_tcp *)((ptrdiff_t)ipptr + (ipptr->ip_hl * 4));
        }
        return tcpptr;
}

/** get a pointer to the TCP header (if any) given a pointer to the IP header
 * @param ip		The IP header
 * @param[out] skipped	An output variable of the number of bytes skipped
 *
 * @returns a pointer to the TCP header, or NULL if this is not a TCP packet
 *
 * Skipped can be NULL, in which case it will be ignored by the program.
 */
struct libtrace_tcp *get_tcp_from_ip(const struct libtrace_ip *ip, int *skipped)
{
#define SW_IP_OFFMASK 0xff1f
	struct libtrace_tcp *tcpptr = 0;

	if ((ip->ip_p == 6) && ((ip->ip_off & SW_IP_OFFMASK) == 0))  {
		tcpptr = (struct libtrace_tcp *)((ptrdiff_t)ip+ (ip->ip_hl * 4));
	}

	if (skipped)
		*skipped=(ip->ip_hl*4);

	return tcpptr;
}

/** get a pointer to the UDP header (if any)
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
        if ((ipptr->ip_p == 17) && ((ipptr->ip_off & SW_IP_OFFMASK) == 0)) {
                udpptr = (struct libtrace_udp *)((ptrdiff_t)ipptr + (ipptr->ip_hl * 4));
        }

        return udpptr;
}

/** get a pointer to the UDP header (if any) given a pointer to the IP header
 * @param ip		The IP header
 * @param[out] skipped	An output variable of the number of bytes skipped
 *
 * @returns a pointer to the UDP header, or NULL if this is not a UDP packet
 *
 * Skipped can be NULL, in which case it will be ignored by the program.
 */
struct libtrace_udp *get_udp_from_ip(const struct libtrace_ip *ip, int *skipped)
{
	struct libtrace_udp *udpptr = 0;

	if ((ip->ip_p == 6) && ((ip->ip_off & SW_IP_OFFMASK) == 0))  {
		udpptr = (struct libtrace_udp *)((ptrdiff_t)ip+ (ip->ip_hl * 4));
	}

	if (skipped)
		*skipped=(ip->ip_hl*4);

	return udpptr;
}


/** get a pointer to the ICMP header (if any)
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
        if ((ipptr->ip_p == 1)&& ((ipptr->ip_off & SW_IP_OFFMASK) == 0 )){
                icmpptr = (struct libtrace_icmp *)((ptrdiff_t)ipptr + (ipptr->ip_hl * 4));
        }
        return icmpptr;
}

/** get a pointer to the ICMP header (if any) given a pointer to the IP header
 * @param ip		The IP header
 * @param[out] skipped	An output variable of the number of bytes skipped
 *
 * @returns a pointer to the ICMP header, or NULL if this is not a ICMP packet
 *
 * Skipped can be NULL, in which case it will be ignored by the program.
 */
struct libtrace_icmp *get_icmp_from_ip(struct libtrace_ip *ip, int *skipped)
{
	struct libtrace_icmp *icmpptr = 0;

	if ((ip->ip_p == 6) && ((ip->ip_off & SW_IP_OFFMASK) == 0))  {
		icmpptr = (struct libtrace_icmp *)((ptrdiff_t)ip+ (ip->ip_hl * 4));
	}

	if (skipped)
		*skipped=(ip->ip_hl*4);

	return icmpptr;
}
/** parse an ip or tcp option
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
				return 0; // I have no idea wtf is going on
					  // with these packets
			(*len)-=*optlen;
			(*data)=(*ptr+2);
			(*ptr)+=*optlen;
			if (*len<0)
				return 0;
			return 1;
	}
	assert(0);
}


/** Get the current time in DAG time format 
 * @param packet 	a pointer to a libtrace_packet structure
 * @returns a 64 bit timestamp in DAG ERF format (upper 32 bits are the seconds
 * past 1970-01-01, the lower 32bits are partial seconds)
 * @author Daniel Lawson
 */ 
uint64_t trace_get_erf_timestamp(const struct libtrace_packet_t *packet) {
	uint64_t timestamp = 0;
	struct timeval ts;

	if (packet->trace->format->get_erf_timestamp) {
		timestamp = packet->trace->format->get_erf_timestamp(packet);
	} else if (packet->trace->format->get_timeval) {
		ts = packet->trace->format->get_timeval(packet);
		timestamp = ((((uint64_t)ts.tv_sec) << 32) + \
				(((uint64_t)ts.tv_usec * UINT_MAX)/1000000));
	}
	return timestamp;
}

/** Get the current time in struct timeval
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns time that this packet was seen in a struct timeval
 * @author Daniel Lawson
 * @author Perry Lorier
 */ 
struct timeval trace_get_timeval(const struct libtrace_packet_t *packet) {
        struct timeval tv;
	uint64_t ts = 0;

	if (packet->trace->format->get_timeval) {
		tv = packet->trace->format->get_timeval(packet);
	} else if (packet->trace->format->get_erf_timestamp) {
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
	}

        return tv;
}

/** Get the current time in floating point seconds
 * @param packet 	a pointer to a libtrace_packet structure
 * @returns time that this packet was seen in 64bit floating point seconds
 * @author Perry Lorier
 */ 
double trace_get_seconds(const struct libtrace_packet_t *packet) {
	double seconds;
	uint64_t ts;
	
	if (packet->trace->format->get_seconds) {
		seconds = packet->trace->format->get_seconds(packet);
	} else if (packet->trace->format->get_erf_timestamp) {
		ts = packet->trace->format->get_erf_timestamp(packet);
		seconds =  (ts>>32) + ((ts & UINT_MAX)*1.0 / UINT_MAX);
	} 
	return seconds;
}

/** Get the size of the packet in the trace
 * @param packet the packet opaque pointer
 * @returns the size of the packet in the trace
 * @author Perry Lorier
 * @note Due to this being a header capture, or anonymisation, this may not
 * be the same size as the original packet.  See trace_get_wire_length() for the 
 * original size of the packet.
 * @note This can (and often is) different for different packets in a trace!
 * @par 
 *  This is sometimes called the "snaplen".
 */ 
int trace_get_capture_length(const struct libtrace_packet_t *packet) {

	if (packet->trace->format->get_capture_length) {
		return packet->trace->format->get_capture_length(packet);
	}
	return -1;
}
	
/** Get the size of the packet as it was seen on the wire.
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns the size of the packet as it was on the wire.
 * @author Perry Lorier
 * @author Daniel Lawson
 * @note Due to the trace being a header capture, or anonymisation this may
 * not be the same as the Capture Len.
 */ 
int trace_get_wire_length(const struct libtrace_packet_t *packet){
	if (packet->trace->format->get_wire_length) {
		return packet->trace->format->get_wire_length(packet);
	}
	return -1;

}

/** Get the type of the link layer
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

/** Get the source MAC addres
 * @param packet 	a pointer to a libtrace_packet structure
 * @returns a pointer to the source mac, (or NULL if there is no source MAC)
 * @author Perry Lorier
 */
uint8_t *trace_get_source_mac(const struct libtrace_packet_t *packet) {
	void *link = trace_get_link(packet);
	struct ieee_802_11_header *wifi = link;
        struct ether_header *ethptr = link;
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

/** Get the destination MAC addres
 * @param packet a libtrace_packet pointer
 * @returns a pointer to the destination mac, (or NULL if there is no 
 * destination MAC)
 * @author Perry Lorier
 */
uint8_t *trace_get_destination_mac(const struct libtrace_packet_t *packet) {
	void *link = trace_get_link(packet);
	struct ieee_802_11_header *wifi = link;
        struct ether_header *ethptr = link;
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


/** process a libtrace event
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
	struct libtrace_eventobj_t event;

	if (!trace) {
		fprintf(stderr,"You called trace_event() with a NULL trace object!\n");
	}
	assert(trace);
	assert(packet);

	/* Store the trace we are reading from into the packet opaque
	 * structure */
	packet->trace = trace;

	/* Is there a packet ready? */
	switch (trace->sourcetype) {
#if HAVE_PCAP
		case INTERFACE:
			{
				int data;
				event.fd = pcap_fileno(trace->input.pcap);
				if(ioctl(event.fd,FIONREAD,&data)==-1){
					perror("ioctl(FIONREAD)");
				}
				if (data>0) {
					event.size = trace_read_packet(trace,packet);
					event.type = TRACE_EVENT_PACKET;
					return event;
				}
				event.type = TRACE_EVENT_IOWAIT;
				return event;
			}
#endif
		case SOCKET:
		case DEVICE:
		case RT:
			{
				int data;
				event.fd = trace->input.fd;
				if(ioctl(event.fd,FIONREAD,&data)==-1){
					perror("ioctl(FIONREAD)");
				}
				if (data>0) {
					event.size = trace_read_packet(trace,packet);
					event.type = TRACE_EVENT_PACKET;
					return event;
				}
				event.type = TRACE_EVENT_IOWAIT;
				return event;
			}
		case STDIN:
		case TRACE:
			{
				double ts;
				double now;
				struct timeval stv;
				/* "Prime" the pump */
				if (!trace->packet.buffer) {
					trace->packet.buffer = malloc(4096);
					trace->packet.size=
						trace_read_packet(trace,packet);
					event.size = trace->packet.size;
					if (trace->packet.size > 0 ) {
						memcpy(trace->packet.buffer,packet->buffer,trace->packet.size);
					} else {
						// return here, the test for event.size will sort out the error
						event.type = TRACE_EVENT_PACKET;
						return event;
					}
				}

				ts=trace_get_seconds(packet);
				if (trace->tdelta!=0) {
					// Get the adjusted current time
					gettimeofday(&stv, NULL);
					now = stv.tv_sec + ((double)stv.tv_usec / 1000000.0);
					now -= trace->tdelta; // adjust for trace delta
					
					
					// if the trace timestamp is still in the future, 
					// return a SLEEP event, otherwise fire the packet
					if (ts > now) {
						event.seconds = ts - trace->trace_last_ts;
						event.type = TRACE_EVENT_SLEEP;
						return event;
					}
				} else {
					gettimeofday(&stv, NULL);
					// work out the difference between the start of trace replay,
					// and the first packet in the trace
					trace->tdelta = stv.tv_sec + ((double)stv.tv_usec / 1000000.0);
					trace->tdelta -= ts;

				}
				
					// This is the first packet, so just fire away.
				packet->size = trace->packet.size;
				memcpy(packet->buffer,trace->packet.buffer,trace->packet.size);

				free(trace->packet.buffer);
				trace->packet.buffer = 0;
				event.type = TRACE_EVENT_PACKET;
				
				trace->trace_last_ts = ts;

				return event;
			}
		default:
			assert(0);
	}
	assert(0);
}

/** setup a BPF filter
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

/** apply a BPF filter
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

		switch (trace_get_link_type(packet)) {
			case TRACE_TYPE_ETH:
				pcap = (pcap_t *)pcap_open_dead(DLT_EN10MB, 1500);
				break;
#ifdef DLT_LINUX_SLL
			case TRACE_TYPE_LINUX_SLL:
				pcap = (pcap_t *)pcap_open_dead(DLT_LINUX_SLL, 1500);
				break;
#endif
#ifdef DLT_PFLOG
			case TRACE_TYPE_PFLOG:
				pcap = (pcap_t *)pcap_open_dead(DLT_PFLOG, 1500);
				break;
#endif
			default:
				printf("only works for ETH and LINUX_SLL (ppp) at the moment\n");
				assert(0);
		}		

		// build filter
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

/** Set the direction flag, if it has one
 * @param packet the packet opaque pointer
 * @param direction the new direction (0,1,2,3)
 * @returns a signed value containing the direction flag, or -1 if this is not supported
 * @author Daniel Lawson
 */
int8_t trace_set_direction(struct libtrace_packet_t *packet, int8_t direction) {


	if (packet->trace->format->set_direction) {
		return packet->trace->format->set_direction(packet,direction);
	}
	return -1;
}

/** Get the direction flag, if it has one
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

	return htons(port->src);
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

	return htons(port->dst);
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
int8_t trace_get_server_port(uint8_t protocol, uint16_t source, uint16_t dest) {
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

	uint16_t server, client;

	/* equal */
	if (source == client)
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
	// failing that test...
	if (source < dest) {
		return USE_SOURCE;
	} 
	return USE_DEST;
	
}

/** Truncate the packet at the suggested length
 * @param packet	the packet opaque pointer
 * @param size		the new length of the packet
 * @returns the new length of the packet, or the original length of the 
 * packet if unchanged
 * NOTE: len refers to the network-level payload of the packet, and not
 * any capture headers included as well. For example, to truncate a packet
 * after the IP header, set scan to sizeof(ethernet_header) + sizeof(ip_header)
 * @author Daniel Lawson
 */
size_t trace_truncate_packet(struct libtrace_packet_t *packet, size_t size) {
	dag_record_t *erfptr;
#if HAVE_PCAP
	struct pcap_pkthdr *pcaphdr;
#endif

	assert(packet);

	if (size > packet->size) {
		// can't make a packet larger
		return packet->size;
	}
	if (packet->trace->format->truncate_packet) {
		return packet->trace->format->truncate_packet(packet,size);
	}
	return -1;
}

