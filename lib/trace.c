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
 */
#define _GNU_SOURCE
#include "common.h"
#include "config.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pcap.h>
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
#include <unistd.h>
#include <net/ethernet.h>
#include <time.h>
#include <sys/ioctl.h>

#ifdef HAVE_STDINT_H
#  include <stdint.h>
#endif

#ifdef HAVE_STDDEF_H
#include <stddef.h>
#else
# error "Can't find stddef.h - do you define ptrdiff_t elsewhere?"
#endif

#include "libtrace.h"
#include "fifo.h"

#ifdef HAVE_PCAP_BPF_H
#  include <pcap-bpf.h>
#else
#  ifdef HAVE_NET_BPF_H
#    include <net/bpf.h>
#  endif
#endif

#include <pcap.h>

#include "dagformat.h"

#include "wag.h"

#include <zlib.h>


typedef enum {SOCKET, TRACE, STDIN, DEVICE, INTERFACE, RT } source_t;

typedef enum {ERF, PCAP, PCAPINT, DAG, RTCLIENT, WAG, WAGINT } format_t;

struct libtrace_filter_t {
	struct bpf_insn *filter;
	char * filterstring;
};

struct libtrace_t {
        format_t format;
        source_t sourcetype;
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
                gzFile *file;
                pcap_t *pcap;
        } input;
        struct fifo_t *fifo;   
	struct {
		void *buffer;
		int size;
	} packet;
	double last_ts;
	double start_ts;
};

#define URI_PROTO_LINE 16
static int init_trace(struct libtrace_t **libtrace, char *uri) {
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

        if (!strncasecmp(scan,"erf",3)) {
                (*libtrace)->format=ERF;
        } else if (!strncasecmp(scan,"pcapint",7)) {
                (*libtrace)->format=PCAPINT;
        } else if (!strncasecmp(scan,"pcap",4)) {
                (*libtrace)->format=PCAP;
        } else if (!strncasecmp(scan,"dag",3)) {
                (*libtrace)->format=DAG;
        } else if (!strncasecmp(scan,"rtclient",7)) {
                (*libtrace)->format=RTCLIENT;
	} else if (!strncasecmp(scan,"wagint",6)) {
		(*libtrace)->format=WAGINT;
	} else if (!strncasecmp(scan,"wag",3)) {
		(*libtrace)->format=WAG;
        } else {
                //badly formed URI
                return 0;
        }
        
        // push uridata past the delimiter
        uridata++;
        
        // libtrace->format now contains the type of uri
        // libtrace->uridata contains the appropriate data for this
        
        switch((*libtrace)->format) {
		case PCAPINT:
		case WAGINT:
			/* Can have uridata of the following format
			 * eth0
			 * etc
			 */
			// We basically assume this is correct.
			(*libtrace)->sourcetype = INTERFACE;	
			(*libtrace)->conn_info.path = strdup(uridata);
			break;
                case PCAP:
                case ERF:
                case WAG:
                case DAG:
                        /*
                         * Can have uridata of the following format
                         * /path/to/socket (probably not PCAP)
                         * /path/to/file
                         * /path/to/file.gz (not PCAP)
			 * /dev/device (use PCAPINT)
                         * -
                         */
                        if (!strncmp(uridata,"-",1)) {
                                (*libtrace)->sourcetype = STDIN;
                        } else {
                                struct stat buf;
                                if (stat(uridata,&buf) == -1) {
                                        perror("stat");
                                        return 0;
                                }
                                if (S_ISSOCK(buf.st_mode)) {
                                        (*libtrace)->sourcetype = SOCKET;
				} else if (S_ISCHR(buf.st_mode)) {
					(*libtrace)->sourcetype = DEVICE;
                                } else {
                                        (*libtrace)->sourcetype = TRACE;
				}
                                (*libtrace)->conn_info.path = strdup(uridata);
                        }
                        break;

                case RTCLIENT:
                        /* 
                         * Can have the uridata in the format
                         * hostname
                         * hostname:port
                         */
                        (*libtrace)->sourcetype = RT;
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
        }
        

        (*libtrace)->fifo = create_fifo(1048576);
	(*libtrace)->packet.buffer = 0;
	(*libtrace)->packet.size = 0;

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
        char errbuf[PCAP_ERRBUF_SIZE];

        if(init_trace(&libtrace,uri) == 0) {
                return 0;
        }
       
        switch(libtrace->sourcetype) {
                case RT: 
                        if ((he=gethostbyname(libtrace->conn_info.rt.hostname)) == NULL) {  
                                perror("gethostbyname");
                                return 0;
                        } 
                        if ((libtrace->input.fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                                perror("socket");
                                return 0;
                        }

                        remote.sin_family = AF_INET;   
                        remote.sin_port = htons(libtrace->conn_info.rt.port);
                        remote.sin_addr = *((struct in_addr *)he->h_addr);
                        bzero(&(remote.sin_zero), 8);

                        if (connect(libtrace->input.fd, (struct sockaddr *)&remote,
                                                sizeof(struct sockaddr)) == -1) {
                                perror("connect (inet)");
                                return 0;
                        }
                        break;
                case TRACE:
                        if (libtrace->format == PCAP) {
                                if ((libtrace->input.pcap = pcap_open_offline(libtrace->conn_info.path, errbuf)) == NULL) {
					fprintf(stderr,"%s\n",errbuf);
					return 0;
				}
                        } else {
                                libtrace->input.file = gzopen(libtrace->conn_info.path, "r");
                        }
                        break;
                case STDIN:
                        if (libtrace->format == PCAP) {
                                libtrace->input.pcap = pcap_open_offline("-",errbuf); 
                        } else {
                                libtrace->input.file = gzdopen(STDIN, "r");
                        }
                        break;
                case SOCKET:
                	/* Pcap doesn't work */
                        if (libtrace->format != PCAP) {
                                if ((libtrace->input.fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
                                        perror("socket");
                                        return 0;
                                }
                                unix_sock.sun_family = AF_UNIX;
                                bzero(unix_sock.sun_path,108);
                                snprintf(unix_sock.sun_path,108,"%s",libtrace->conn_info.path);

                                if (connect(libtrace->input.fd, (struct sockaddr *)&unix_sock,
                                                        sizeof(struct sockaddr)) == -1) {
                                        perror("connect (unix)");
                                        return 0;
                                }
                        }
                        break;
                case DEVICE:
		case INTERFACE:
			switch (libtrace->format) {
				case PCAPINT:
				case PCAP:
					libtrace->input.pcap = pcap_open_live(
						libtrace->conn_info.path,
						4096,
						1,
						0,
						errbuf);
					break;
				default:
					fprintf(stderr,"Unknown format trace, hoping I can just read\n");
				case WAGINT:
				case WAG:
					libtrace->input.fd = open(
						libtrace->conn_info.path,
						O_RDONLY);
					break;
			}
			break;
                default:
                        fprintf(stderr,"Unsupported source type for libtrace, terminating (%i)\n",libtrace->sourcetype);
                        exit(0);
                
        }
        return libtrace;
}

/** Close a trace file, freeing up any resources it may have been using
 *
 */
void trace_destroy(struct libtrace_t *libtrace) {
        assert(libtrace);
        if (libtrace->format == PCAP || libtrace->format == PCAPINT) {
                pcap_close(libtrace->input.pcap);
        } else if (libtrace->sourcetype == SOCKET || libtrace->sourcetype == RT) {
                close(libtrace->input.fd);
        } else {
                gzclose(libtrace->input.file);
        }       
        // need to free things!
        destroy_fifo(libtrace->fifo);
        free(libtrace);
}

static int trace_read(struct libtrace_t *libtrace, void *buffer, size_t len) {
        int numbytes;
        assert(libtrace);
        assert(len >= 0);

        if (buffer == 0)
                buffer = malloc(len);

	switch(libtrace->sourcetype) {
		case SOCKET:
		case RT:
                	// read from the network
                	if ((numbytes=recv(libtrace->input.fd, 
							buffer, 
							len, 
							0)) == -1) {
                        	perror("recv");
                        	return -1;
                	}
			break;
		case DEVICE:
			if ((numbytes=read(libtrace->input.fd, 
							buffer, 
							len)) == -1) {
				perror("read");
				return -1;
			}
			break;
		default:
                	if ((numbytes=gzread(libtrace->input.file,
							buffer,
							len)) == -1) {
                        	perror("gzread");
                        	return -1;
                	}
	}
        return numbytes;

}

/** Read one packet from the trace into buffer
 *
 * @param libtrace 	the libtrace opaque pointer
 * @param packet  	the packet opaque pointer
 * @returns false if it failed to read a packet
 *
 */
int trace_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
        int numbytes;
        int size;
        char buf[4096];
        struct pcap_pkthdr pcaphdr;
        const u_char *pcappkt;
	int read_required = 0;

	void *buffer = 0;
	if (!libtrace) {
		fprintf(stderr,"Oi! You called trace_read_packet() with a NULL libtrace parameter!\n");
	}
        assert(libtrace);
        assert(packet);

	//bzero(buffer,len);
      
	/* Store the trace we are reading from into the packet opaque 
	 * structure */
	packet->trace = libtrace;

	buffer = packet->buffer;
	/* PCAP gives us it's own per-packet interface. Let's use it */
        if (libtrace->format == PCAP || libtrace->format == PCAPINT) {
                if ((pcappkt = pcap_next(libtrace->input.pcap, &pcaphdr)) == NULL) {
                        return -1;
                }
                memcpy(buffer,&pcaphdr,sizeof(struct pcap_pkthdr));
                memcpy(buffer + sizeof(struct pcap_pkthdr),pcappkt,pcaphdr.len);
                numbytes = pcaphdr.len;
	
		packet->size = numbytes + sizeof(struct pcap_pkthdr);
		return numbytes;
        } 

	/* If we're reading from an ERF input, it's an offline trace. We can make some assumptions */
 	
	if (libtrace->format == ERF) {
		void *buffer2 = buffer;
		// read in the trace header
		if ((numbytes=gzread(libtrace->input.file,
						buffer,
						sizeof(dag_record_t))) == -1) {
			perror("gzread");
			return -1;
		}
		if (numbytes == 0) {
			return 0;
		}
		size = ntohs(((dag_record_t *)buffer)->rlen) - sizeof(dag_record_t);
		assert(size < LIBTRACE_PACKET_BUFSIZE);
		buffer2 = (ptrdiff_t)buffer +  sizeof(dag_record_t);

		// read in the rest of the packet
		if ((numbytes=gzread(libtrace->input.file,
						buffer2,
						size)) == -1) {
			perror("gzread");
			return -1;
		}
		packet->size = numbytes + sizeof(dag_record_t);
		return sizeof(dag_record_t) + numbytes;
	}
	
	do {
		if (fifo_out_available(libtrace->fifo) == 0 || read_required) {
			if ((numbytes = trace_read(libtrace,buf,4096))<=0){
				return numbytes; 
			}
			fifo_write(libtrace->fifo,buf,numbytes);

			read_required = 0;
		}

		switch (libtrace->format) {
			case RTCLIENT:
				// only do this if we're reading from the RT interface
				if (fifo_out_read(libtrace->fifo, &packet->status, sizeof(int)) == 0) {
					read_required = 1;
					continue;
				}

				fifo_out_update(libtrace->fifo,sizeof(int));

				/* FALL THRU */
			case ERF:
			case DAG:
				// read in the erf header
				if ((numbytes = fifo_out_read(libtrace->fifo, buffer, sizeof(dag_record_t))) == 0) {
					fifo_out_reset(libtrace->fifo);
					read_required = 1;
					continue;
				}

				size = ntohs(((dag_record_t *)buffer)->rlen);
				break;
			case WAG:
				if ((numbytes = fifo_out_read(libtrace->fifo,
								&size,
								sizeof(size))) 
								== 0) {
					fifo_out_reset(libtrace->fifo);
					read_required = 1;
					continue;
				}
				size*=4;
				break;
			default:
				fprintf(stderr,"Unknown type in _read()\n");
				assert(0);
		}

		assert(size < LIBTRACE_PACKET_BUFSIZE);

		// read in the full packet
		if ((numbytes = fifo_out_read(libtrace->fifo, buffer, size)) == 0) {
			fifo_out_reset(libtrace->fifo);
			read_required = 1;
			continue;
		}

		// got in our whole packet, so...
		fifo_out_update(libtrace->fifo,size);

		if (libtrace->sourcetype == SOCKET || libtrace->sourcetype == RT) {
			fifo_ack_update(libtrace->fifo,size + sizeof(int));
		} else {
			fifo_ack_update(libtrace->fifo,size);
		}
		
		packet->size = numbytes;
        	return numbytes;

	} while (1);
}


/** get a pointer to the link layer
 * @param libtrace	a pointer to the trace object returned from gettrace
 * @param buffer	a pointer to a filled in buffer
 * @param buflen	a pointer to the size of the buffer
 *
 * @returns a pointer to the link layer, or NULL if there is no link layer
 * you should call trace_get_link_type() to find out what type of link layer this is
 */
void *trace_get_link(struct libtrace_packet_t *packet) {
        void *ethptr = 0;
	
	struct wag_event_t *event = (struct wag_event_t *)packet->buffer;
	struct wag_data_event_t *data_event;
	
        
        switch(packet->trace->format) {
                case ERF:
                case DAG:
                case RTCLIENT:
			if (trace_get_link_type(packet)==TRACE_TYPE_ETH) 
                        	ethptr = ((uint8_t *)packet->buffer + 
						dag_record_size + 2);
			else
				ethptr = ((uint8_t *)packet->buffer + 
						dag_record_size + 2);
                        break;
		case PCAPINT:
		case PCAP:
                        ethptr = (struct ether_header *)(packet->buffer + sizeof(struct pcap_pkthdr));
                        break;
		case WAGINT:
		case WAG:
			switch (event->type) {
				case 0x0:
					data_event = (void*)&(event->payload);
					return data_event->data;
				default:
					fprintf(stderr,"Unknown WAG Event (0x%08x)\n",event->type);
					return NULL;
			}
			
		default:
			fprintf(stderr,"Dunno this trace format\n");
			assert(0);
        }
        return ethptr;
}

/** get a pointer to the IP header (if any)
 * @param libtrace	a pointer to the trace object returned from gettrace
 * @param buffer	a pointer to a filled in buffer
 * @param buflen	a pointer to the size of the buffer
 *
 * @returns a pointer to the IP header, or NULL if there is not an IP packet
 */
struct libtrace_ip *trace_get_ip(struct libtrace_packet_t *packet) {
        struct libtrace_ip *ipptr = 0;

	switch(trace_get_link_type(packet)) {
		case TRACE_TYPE_80211:
			{ 
				
				struct ieee_802_11_header *wifi = trace_get_link(packet);	

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
				if (ntohs(eth->ether_type)!=0x0800) {
					ipptr = NULL;
				}
				else {
					ipptr = ((void *)eth) + 14;
				}
				break;
			}
		case TRACE_TYPE_ATM:
			{
				struct atm_rec *atm = 
					trace_get_link(packet);
				// TODO: Find out what ATM does, and return
				//       NULL for non IP data
				//       Presumably it uses the normal stuff
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


/** get a pointer to the TCP header (if any)
 * @param libtrace	a pointer to the trace object returned from gettrace
 * @param buffer	a pointer to a filled in buffer
 * @param buflen	a pointer to the size of the buffer
 *
 * @returns a pointer to the TCP header, or NULL if there is not a TCP packet
 */
struct libtrace_tcp *trace_get_tcp(struct libtrace_packet_t *packet) {
        struct libtrace_tcp *tcpptr = 0;
        struct libtrace_ip *ipptr = 0;

        if(!(ipptr = trace_get_ip(packet))) {
                return 0;
        }
        if (ipptr->ip_p == 6) {
                tcpptr = (struct libtrace_tcp *)((ptrdiff_t)ipptr + (ipptr->ip_hl * 4));
        }
        return tcpptr;
}

/** get a pointer to the UDP header (if any)
 * @param libtrace	a pointer to the trace object returned from gettrace
 * @param buffer	a pointer to a filled in buffer
 * @param buflen	a pointer to the size of the buffer
 *
 * @returns a pointer to the UDP header, or NULL if this is not a UDP packet
 */
struct libtrace_udp *trace_get_udp(struct libtrace_packet_t *packet) {
        struct libtrace_udp *udpptr = 0;
        struct libtrace_ip *ipptr = 0;
        
        if(!(ipptr = trace_get_ip(packet))) {
                return 0;
        }
        if (ipptr->ip_p == 17) {
                udpptr = (struct libtrace_udp *)((ptrdiff_t)ipptr + (ipptr->ip_hl * 4));
        }
        return udpptr;
}

/** get a pointer to the ICMP header (if any)
 * @param libtrace	a pointer to the trace object returned from gettrace
 * @param buffer	a pointer to a filled in buffer
 * @param buflen	a pointer to the size of the buffer
 *
 * @returns a pointer to the ICMP header, or NULL if this is not a ICMP packet
 */
struct libtrace_icmp *trace_get_icmp(struct libtrace_packet_t *packet) {
        struct libtrace_icmp *icmpptr = 0;
        struct libtrace_ip *ipptr = 0;
        
        if(!(ipptr = trace_get_ip(packet))) {
                return 0;
        }
        if (ipptr->ip_p == 1) {
                icmpptr = (struct libtrace_icmp *)((ptrdiff_t)ipptr + (ipptr->ip_hl * 4));
        }
        return icmpptr;
}

/** Get the current time in DAG time format 
 * @param libtrace the libtrace opaque pointer
 * @param buffer a pointer to a filled in buffer
 * @param buflen the length of the buffer
 * @returns a 64 bit timestamp in DAG ERF format (upper 32 bits are the seconds
 * past 1970-01-01, the lower 32bits are partial seconds)
 * @author Daniel Lawson
 */ 
uint64_t trace_get_erf_timestamp(struct libtrace_packet_t *packet) {
	uint64_t timestamp = 0;
        dag_record_t *erfptr = 0;
        struct pcap_pkthdr *pcapptr = 0;
	struct wag_event_t *wagptr = 0;
        switch (packet->trace->format) {
                case DAG:
                case ERF:
                case RTCLIENT:
                        erfptr = (dag_record_t *)packet->buffer;
			timestamp = erfptr->ts;
                        break;
		case PCAPINT:
                case PCAP:
                        pcapptr = (struct pcap_pkthdr *)packet->buffer;
			timestamp = ((((uint64_t)pcapptr->ts.tv_sec) << 32) + \
				(pcapptr->ts.tv_usec*UINT_MAX/1000000));
                        break;
		case WAGINT:
		case WAG:
			wagptr = (struct wag_event_t *)packet->buffer;
			timestamp = wagptr->timestamp_lo;
			timestamp |= (uint64_t)wagptr->timestamp_hi<<32;
			timestamp = ((timestamp%44000000)*(UINT_MAX/44000000))
				  | ((timestamp/44000000)<<32);
			break;
		default:
			fprintf(stderr,"Unknown format in trace_get_erf_timestamp\n");
			timestamp = 0;
        }
        return timestamp;
}

/** Get the current time in struct timeval
 * @param libtrace the libtrace opaque pointer
 * @param buffer a pointer to a filled in buffer
 * @param buflen the length of the buffer
 * @returns time that this packet was seen in a struct timeval
 * @author Daniel Lawson
 * @author Perry Lorier
 */ 
struct timeval trace_get_timeval(struct libtrace_packet_t *packet) {
        struct timeval tv;
        struct pcap_pkthdr *pcapptr = 0;
	uint64_t ts;
	//uint32_t seconds;
        switch (packet->trace->format) {
		case PCAPINT:
                case PCAP:
                        pcapptr = (struct pcap_pkthdr *)packet->buffer;
                        tv = pcapptr->ts;
                        break;
		case WAGINT:
		case WAG:
                case DAG:
                case ERF:
                case RTCLIENT:
		default:
			// FIXME: This isn't portable to big-endian machines
			ts = trace_get_erf_timestamp(packet);
			tv.tv_sec = ts >> 32;		
			ts = (1000000 * (ts & 0xffffffffULL));
        		ts += (ts & 0x80000000ULL) << 1;
        		tv.tv_usec = ts >> 32;
        		if (tv.tv_usec >= 1000000) {
                		tv.tv_usec -= 1000000;
                		tv.tv_sec += 1;
        		}
			break;
        }
        return tv;
}

/** Get the current time in floating point seconds
 * @param libtrace the libtrace opaque pointer
 * @param buffer a pointer to a filled in buffer
 * @param buflen the length of the buffer
 * @returns time that this packet was seen in 64bit floating point seconds
 * @author Perry Lorier
 */ 
double trace_get_seconds(struct libtrace_packet_t *packet) {
	uint64_t ts;
	ts = trace_get_erf_timestamp(packet);
	return (ts>>32) + ((ts & UINT_MAX)*1.0 / UINT_MAX);
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
int trace_get_capture_length(struct libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	struct pcap_pkthdr *pcapptr = 0;
	struct wag_event_t *wag_event;
	switch (packet->trace->format) {
		case DAG:
		case ERF:
		case RTCLIENT:
			erfptr = (dag_record_t *)packet->buffer;
			return ntohs(erfptr->rlen);
		case PCAPINT:
		case PCAP:
			pcapptr = (struct pcap_pkthdr *)packet->buffer;
			//return ntohs(pcapptr->caplen);
			return pcapptr->caplen;
		case WAGINT:
		case WAG:
			wag_event = (struct wag_event_t *)packet->buffer;
			switch(wag_event->type) {
				case 0:
					return wag_event->length*4-(
						sizeof(struct wag_event_t)+
						sizeof(struct wag_data_event_t)
						);
				default:
					assert(0);
			}
		default:
			assert(0);
	}
	return -1;
}
	
/** Get the size of the packet as it was seen on the wire.
 * @param libtrace the libtrace opaque pointer
 * @param buffer a pointer to a filled in buffer
 * @param buflen the length of the buffer
 * @returns the size of the packet as it was on the wire.
 * @author Perry Lorier
 * @author Daniel Lawson
 * @note Due to the trace being a header capture, or anonymisation this may
 * not be the same as the Capture Len.
 */ 
int trace_get_wire_length(struct libtrace_packet_t *packet){
	dag_record_t *erfptr = 0;
	struct pcap_pkthdr *pcapptr = 0;
	struct wag_event_t *wag_event = 0;
	switch (packet->trace->format) {
		case DAG:
		case ERF:
		case RTCLIENT:
			erfptr = (dag_record_t *)packet->buffer;
			return ntohs(erfptr->wlen);
			break;
		case PCAPINT:
		case PCAP:
			pcapptr = (struct pcap_pkthdr *)packet->buffer;
			return ntohs(pcapptr->len);
		 	break;
		case WAGINT:
		case WAG:
			wag_event = (struct wag_event_t *)packet->buffer;
			switch(wag_event->type) {
				case 0:
					return ((struct wag_data_event_t *)(&wag_event->payload))->frame_length;
				default:
					assert(0);
			}
	}
	return -1;

}

/** Get the type of the link layer
 * @param libtrace the libtrace opaque pointer
 * @param buffer a pointer to a filled in buffer
 * @param buflen the length of the buffer
 * @returns libtrace_linktype_t
 * @author Perry Lorier
 * @author Daniel Lawson
 */
libtrace_linktype_t trace_get_link_type(struct libtrace_packet_t *packet ) {
	dag_record_t *erfptr = 0;
	struct pcap_pkthdr *pcapptr = 0;
	int linktype = 0;
	switch (packet->trace->format) {
		case DAG:
		case ERF:
		case RTCLIENT:
			erfptr = (dag_record_t *)packet->buffer;
			switch (erfptr->type) {
				case TYPE_ETH: return TRACE_TYPE_ETH;
				case TYPE_ATM: return TRACE_TYPE_ATM;
				default: assert(0);
			}
			return erfptr->type;
			
			break;
		case PCAPINT:
		case PCAP:
			pcapptr = (struct pcap_pkthdr *)packet->buffer;
			linktype = pcap_datalink(packet->trace->input.pcap);
			switch (linktype) {
				case 1:
					return TRACE_TYPE_ETH; 
				case 11:
					return TRACE_TYPE_ATM;
				case DLT_IEEE802_11:
					return TRACE_TYPE_80211;
			}
		 	break;
		case WAGINT:
		case WAG:
			return TRACE_TYPE_80211;
	}
	return -1;
}

/** Get the source MAC addres
 * @param libtrace the libtrace opaque pointer
 * @param buffer a pointer to a filled in buffer
 * @param buflen the length of the buffer
 * @returns a pointer to the source mac, (or NULL if there is no source MAC)
 * @author Perry Lorier
 */
uint8_t *trace_get_source_mac(struct libtrace_packet_t *packet) {
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
 * @param libtrace the libtrace opaque pointer
 * @param buffer a pointer to a filled in buffer
 * @param buflen the length of the buffer
 * @returns a pointer to the destination mac, (or NULL if there is no 
 * destination MAC)
 * @author Perry Lorier
 */
uint8_t *trace_get_destination_mac(struct libtrace_packet_t *packet) {
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
 * @param libtrace the libtrace opaque pointer
 * @param fd a pointer to a file descriptor to listen on
 * @param seconds a pointer the time in seconds since to the next event
 * @param buffer a pointer to a filled in buffer
 * @param len the length of the buffer
 * @param size the size of the event 
 * @returns
 *  TRACE_EVENT_IOWAIT	Waiting on I/O on <fd>
 *  TRACE_EVENT_SLEEP	Next event in <seconds>
 *  TRACE_EVENT_PACKET	Packet arrived in <buffer> with size <size>
 * FIXME currently keeps a copy of the packet inside the trace pointer,
 * which in turn is stored inside the new packet object...
 * @author Perry Lorier
 */
libtrace_event_t libtrace_event(struct libtrace_t *trace, 
		struct libtrace_packet_t *packet,
			int *fd,double *seconds) {
	*seconds = 0;
	*fd = 0;
	/* Is there a packet ready? */
	switch (trace->sourcetype) {
		case INTERFACE:
			{
				int data;
				*fd = pcap_fileno(trace->input.pcap);
				if(ioctl(*fd,FIONREAD,&data)==-1){
					perror("ioctl(FIONREAD)");
				}
				if (data>0) {
					return TRACE_EVENT_PACKET;
				}
				return TRACE_EVENT_IOWAIT;
			}
		case SOCKET:
		case DEVICE:
		case RT:
			{
				int data;
				if(ioctl(trace->input.fd,FIONREAD,&data)==-1){
					perror("ioctl(FIONREAD)");
				}
				if (data>0) {
					return TRACE_EVENT_PACKET;
				}
				*fd = trace->input.fd;
				return TRACE_EVENT_IOWAIT;
			}
		case STDIN:
		case TRACE:
			{
				double ts;
				/* "Prime" the pump */
				if (!trace->packet.buffer) {
					trace->packet.buffer = malloc(4096);
					trace->packet.size=
						trace_read_packet(trace,packet);
				}
				ts=trace_get_seconds(packet);
				if (trace->last_ts!=0) {
					*seconds = ts - trace->last_ts;
					if (*seconds>time(NULL)-trace->start_ts)
						return TRACE_EVENT_SLEEP;
				}
				else {
					trace->start_ts = time(NULL);
					trace->last_ts = ts;
				}

				packet->size = trace->packet.size;
				memcpy(packet->buffer,trace->packet.buffer,trace->packet.size);

				free(trace->packet.buffer);
				trace->packet.buffer = 0;
				return TRACE_EVENT_PACKET;
			}
		default:
			assert(0);
	}
	/* Shouldn't get here */
	assert(0);
}

/** setup a BPF filter
 * @param filterstring a char * containing the bpf filter string
 * @returns opaque pointer pointer to a libtrace_filter_t object
 * @author Daniel Lawson
 */
struct libtrace_filter_t *trace_bpf_setfilter(const char *filterstring) {
	struct libtrace_filter_t *filter = malloc(sizeof(struct libtrace_filter_t));
	filter->filterstring = strdup(filterstring);
	filter->filter = 0;
	return filter;
}

/** apply a BPF filter
 * @param libtrace the libtrace opaque pointer
 * @param filter the filter opaque pointer
 * @param buffer a pointer to a filled buffer
 * @param buflen the length of the buffer
 * @returns 0 if the filter fails, 1 if it succeeds
 * @author Daniel Lawson
 */
int trace_bpf_filter(struct libtrace_filter_t *filter,
			struct libtrace_packet_t *packet) {
	
	void *linkptr = 0;
	int clen = 0;
	assert(filter);
	assert(packet);
	linkptr = trace_get_link(packet);	
	assert(linkptr);
	clen = trace_get_capture_length(packet);
	

	if (filter->filterstring && ! filter->filter) {
		pcap_t *pcap;
		struct bpf_program bpfprog;

		switch (trace_get_link_type(packet)) {
			case TRACE_TYPE_ETH:
				pcap = pcap_open_dead(DLT_EN10MB, 1500);
				break;
			default:
				printf("only works for ETH at the moment\n");
				assert(0);
		}		

		// build filter
		if (pcap_compile( pcap, &bpfprog, filter->filterstring, 1, 0)) {
			printf("bpf compilation error: %s\n", 
				pcap_geterr(pcap));
			assert(0);
		}
		pcap_close(pcap);
		filter->filter = bpfprog.bf_insns;	
	}

	assert(filter->filter);
	return bpf_filter(filter->filter, linkptr, clen, clen);
	
}

/** Get the direction flag, if it has one
 * @param libtrace the libtrace opaque pointer
 * @param buffer a point to a fille in buffer
 * @param buflen the length of the buffer
 * @returns a signed value containing the direction flag, or -1 if this is not supported
 * @author Daniel Lawson
 */
int8_t trace_get_direction(struct libtrace_packet_t *packet) {
	
	int8_t direction;
	dag_record_t *erfptr = 0;
	assert(packet);

	switch(packet->trace->format) {
		case DAG:
		case ERF:
		case RTCLIENT:
			erfptr = (dag_record_t *)packet->buffer;
			direction = erfptr->flags.iface;
			break;
		default:
			direction = -1;
	}
	
	return direction;
	
	
}


/** Attempt to deduce the 'server' port
 * @param protocol the IP protocol (eg, 6 or 17 for TCP or UDP)
 * @param source the TCP or UDP source port
 * @param dest the TCP or UDP destination port
 * @returns a hint as to which port is the server port
 * @author Daniel Lawson
 */
#define ROOT_SERVER(x) (x < 512)
#define ROOT_CLIENT(x) (512 <= x < 1024)
#define NONROOT_SERVER(x) (x >= 5000)
#define NONROOT_CLIENT(x) (1024 <= x < 5000)
#define DYNAMIC(x) (49152 < x < 65535)
#define SERVER(x) ROOT_SERVER(x) || NONROOT_SERVER(x)
#define CLIENT(x) ROOT_CLIENT(x) || NONROOT_CLIENT(x) || DYNAMIC(x)

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

	int8_t server, client;

	if (SERVER(source) && CLIENT(dest)) {
		return USE_SOURCE;
	} else if (SERVER(dest) && CLIENT(SOURCE)) {
		return USE_DEST;
	} else if (ROOT_SERVER(source) && !ROOT_SERVER(dest)) {
		return USE_SOURCE;
	} else if (ROOT_SERVER(dest) && !ROOT_SERVER(source)) {
		return USE_DEST;
	}
	
	// failing that test...
	if (source < dest) {
		return USE_SOURCE;
	} 
	return USE_DEST;
	
}
