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
#include <net/ethernet.h>
#include <time.h>
#include <sys/ioctl.h>

#ifdef HAVE_STDINT_H
#  include <stdint.h>
#else
#  error "Can't find stdint.h - you need to replace this"
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


typedef enum {SOCKET, TRACE, STDIN, DEVICE, INTERFACE, RT } source_t;

typedef enum {ERF, PCAP, PCAPINT, DAG, RTCLIENT, WAG, WAGINT } format_t;

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

/** The information about traces that are open 
 * @internal
 */
struct libtrace_t {
        format_t format; 	/**< The format that this trace is in */
        source_t sourcetype;	/**< The type (device,file, etc */
        union {
		/** Information about rtclients */
                struct {
                        char *hostname;
                        short port;
                } rt;
                char *path;		/**< information for local sockets */
                char *interface;	/**< intormation for reading of network
					     interfaces */
        } conn_info;
	/** Information about the current state of the input device */
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
        } input;
        struct fifo_t *fifo;   
	struct {
		void *buf; 
		unsigned bottom;
		unsigned top;
		unsigned diff;
		unsigned curr;
		unsigned offset;
	} dag;
	struct {
		void *buffer;
		int size;
	} packet;
	double last_ts;
	double start_ts;
};

struct trace_sll_header_t {
	uint16_t pkttype;          	/* packet type */
	uint16_t hatype;           	/* link-layer address type */
	uint16_t halen;            	/* link-layer address length */
	char addr[8];	 		/* link-layer address */
	uint16_t protocol;         	/* protocol */
};

#define RP_BUFSIZE 65536

#define URI_PROTO_LINE 16
static int init_trace(struct libtrace_t **libtrace, char *uri) {
        char *scan = calloc(sizeof(char),URI_PROTO_LINE);
        char *uridata = 0;                  
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

        if (!strncasecmp(scan,"erf",3)) {
                (*libtrace)->format=ERF;
#if HAVE_PCAP
        } else if (!strncasecmp(scan,"pcapint",7)) {
                (*libtrace)->format=PCAPINT;
        } else if (!strncasecmp(scan,"pcap",4)) {
                (*libtrace)->format=PCAP;
#else
        } else if (!strncasecmp(scan,"pcap",4)) { // also catches pcapint
		fprintf(stderr,"This version of libtrace has been compiled without PCAP support\n");
		return 0;
#endif
	
#if HAVE_DAG
	} else if (!strncasecmp(scan,"dag",3)) {
                (*libtrace)->format=DAG;
#else 
	} else if (!strncasecmp(scan,"dag",3)) {
		fprintf(stderr,"This version of libtrace has been compiled without DAG support\n");
		return 0;
#endif
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
#if HAVE_PCAP
		case PCAPINT:
#endif
		case WAGINT:
			/* Can have uridata of the following format
			 * eth0
			 * etc
			 */
			// We basically assume this is correct.
			(*libtrace)->sourcetype = INTERFACE;	
			(*libtrace)->conn_info.path = strdup(uridata);
			break;
#if HAVE_PCAP
                case PCAP:
#endif
                case ERF:
                case WAG:
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
                case DAG:
#if HAVE_DAG
			/* 
			 * Can have uridata of the following format:
			 * /dev/device
			 */
			if (stat(uridata,&buf) == -1) {
				perror("stat");
				return 0;
			}
			if (S_ISCHR(buf.st_mode)) {
				(*libtrace)->sourcetype = DEVICE;
			} else {
				fprintf(stderr,"%s isn't a valid char device, exiting\n",uridata);
				exit(1);
			}
			(*libtrace)->conn_info.path = strdup(uridata);
#endif
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
	assert( (*libtrace)->fifo);
	//(*libtrace)->packet.buffer = 0;
	//(*libtrace)->packet.size = 0;

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
#if HAVE_PCAP
                        if (libtrace->format == PCAP) {
                                if ((libtrace->input.pcap = pcap_open_offline(libtrace->conn_info.path, errbuf)) == NULL) {
					fprintf(stderr,"%s\n",errbuf);
					return 0;
				}
                        } else {
#else
			{
#endif
#if HAVE_ZLIB
                                libtrace->input.file = gzopen(libtrace->conn_info.path, "r");
#else
				libtrace->input.file = fopen(libtrace->conn_info.path, "r");
#endif
			}
                        break;
                case STDIN:
#if HAVE_PCAP
                        if (libtrace->format == PCAP) {
                                libtrace->input.pcap = pcap_open_offline("-",errbuf); 
                        } else {
#else
			{
#endif
#if HAVE_ZLIB
                                libtrace->input.file = gzdopen(STDIN, "r");
#else	
				libtrace->input.file = stdin;
#endif
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
#if HAVE_PCAP
				case PCAPINT:
				case PCAP:
					libtrace->input.pcap = pcap_open_live(
						libtrace->conn_info.path,
						4096,
						1,
						0,
						errbuf);
					break;
#endif
				case WAGINT:
				case WAG:
					libtrace->input.fd = open(
						libtrace->conn_info.path,
						O_RDONLY);
					break;
#if HAVE_DAG
				case DAG:
					if((libtrace->input.fd = dag_open(libtrace->conn_info.path)) < 0) {
						fprintf(stderr,"Cannot open DAG %s: %m\n", libtrace->conn_info.path,errno);
						exit(0);
					}
					if((libtrace->dag.buf = dag_mmap(libtrace->input.fd)) == MAP_FAILED) {
						fprintf(stderr,"Cannot mmap DAG %s: %m\n", libtrace->conn_info.path,errno);
						exit(0);
					}
					if(dag_start(libtrace->input.fd) < 0) {
						fprintf(stderr,"Cannot start DAG %s: %m\n", libtrace->conn_info.path,errno);
						exit(0);
					}
					break;
#endif
				default:
					fprintf(stderr,"Unknown format trace, hoping I can just read\n");
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
#if HAVE_PCAP
        if (libtrace->format == PCAP || libtrace->format == PCAPINT) {
                pcap_close(libtrace->input.pcap);
#else 
	if (0) {
#endif
        } else if (libtrace->sourcetype == SOCKET || libtrace->sourcetype == RT) {
                close(libtrace->input.fd);
#if HAVE_DAG
	} else if (libtrace->format == DAG) {
		dag_stop(libtrace->input.fd);
#endif
        } else {
#if HAVE_ZLIB
                gzclose(libtrace->input.file);
#else	
		fclose(libtrace->input.file);	
#endif
        }       
        // need to free things!
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
				switch(libtrace->format) {
#if HAVE_DAG
					case DAG:

						libtrace->dag.bottom = libtrace->dag.top;
						libtrace->dag.top = dag_offset(
								libtrace->input.fd,
								&(libtrace->dag.bottom),
								0);
						libtrace->dag.diff = libtrace->dag.top -
							libtrace->dag.bottom;
						
						numbytes=libtrace->dag.diff;
						libtrace->dag.offset = 0;
						
						break;
#endif
					default:
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
        char buf[RP_BUFSIZE];
#if HAVE_PCAP
        struct pcap_pkthdr pcaphdr;
        const u_char *pcappkt;
#endif
	dag_record_t *erfptr;
	int read_required = 0;

	void *buffer = 0;
	if (!libtrace) {
		fprintf(stderr,"Oi! You called trace_read_packet() with a NULL libtrace parameter!\n");
	}
        assert(libtrace);
        assert(packet);
      
	/* Store the trace we are reading from into the packet opaque 
	 * structure */
	packet->trace = libtrace;

	buffer = packet->buffer;
#if HAVE_PCAP
	/* PCAP gives us it's own per-packet interface. Let's use it */
        if (libtrace->format == PCAP || libtrace->format == PCAPINT) {
                if ((pcappkt = pcap_next(libtrace->input.pcap, &pcaphdr)) == NULL) {
                        return 0;
                }
                memcpy(buffer,&pcaphdr,sizeof(struct pcap_pkthdr));
                memcpy(buffer + sizeof(struct pcap_pkthdr),pcappkt,pcaphdr.len);
                numbytes = pcaphdr.len;
	
		packet->size = numbytes + sizeof(struct pcap_pkthdr);
		return numbytes;
        } 
#endif 

	/* If we're reading from an ERF input, it's an offline trace. We can make some assumptions */
	if (libtrace->format == ERF) {
		void *buffer2 = buffer;
		int rlen;
		// read in the trace header
		if ((numbytes=gzread(libtrace->input.file,
						buffer,
						dag_record_size)) == -1) {
			perror("gzread");
			return -1;
		}
		if (numbytes == 0) {
			return 0;
		}
		rlen = ntohs(((dag_record_t *)buffer)->rlen);
		size = rlen - dag_record_size;
		assert(size < LIBTRACE_PACKET_BUFSIZE);
		buffer2 = buffer +  dag_record_size;

		// read in the rest of the packet
		if ((numbytes=gzread(libtrace->input.file,
						buffer2,
						size)) == -1) {
			perror("gzread");
			return -1;
		}
		//if ((numbytes + dag_record_size) != rlen) {
		//	printf("read %d wanted %d\n",numbytes +dag_record_size, rlen);
		//}
		packet->size = rlen;
			
		return rlen;
	}

#if HAVE_DAG
	if (libtrace->format == DAG) {
		if (libtrace->dag.diff == 0) {
			if ((numbytes = trace_read(libtrace,buf,RP_BUFSIZE)) <= 0) 
				return numbytes;
		}
		// DAG always gives us whole packets.

		erfptr = (dag_record_t *) ((void *)libtrace->dag.buf + (libtrace->dag.bottom + libtrace->dag.offset));
		size = ntohs(erfptr->rlen);

		if ( size  > LIBTRACE_PACKET_BUFSIZE) {
			printf("%d\n",size);
			assert( size < LIBTRACE_PACKET_BUFSIZE);
		}

		// have to copy it out of the memory hole at this stage:
		memcpy(packet->buffer, erfptr, size);

		packet->size = size;
		libtrace->dag.offset += size;
		libtrace->dag.diff -= size;
		
		assert(libtrace->dag.diff >= 0);
		//assert(libtrace->dag.offset <= libtrace->dag.top);
		return (size);
		
	}
#endif
	do {
		if (fifo_out_available(libtrace->fifo) == 0 || read_required) {
			if ((numbytes = trace_read(libtrace,buf,RP_BUFSIZE))<=0){
				return numbytes; 
			}
			assert(libtrace->fifo);
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
			//case DAG:
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
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns a pointer to the link layer, or NULL if there is no link layer
 * you should call trace_get_link_type() to find out what type of link layer this is
 */
void *trace_get_link(const struct libtrace_packet_t *packet) {
        const void *ethptr = 0;
	dag_record_t *erfptr = 0;
	struct wag_event_t *event = (struct wag_event_t *)packet->buffer;
	struct wag_data_event_t *data_event;
	
        
        switch(packet->trace->format) {
                case ERF:
                case DAG:
                case RTCLIENT:
			erfptr = (dag_record_t *)packet->buffer;
			if (erfptr->flags.rxerror == 1) {
				return NULL;
			}
			if (trace_get_link_type(packet)==TRACE_TYPE_ETH) 
                        	ethptr = ((uint8_t *)packet->buffer + 
						dag_record_size + 2);
			else
				ethptr = ((uint8_t *)packet->buffer + 
						dag_record_size + 2);
                        break;
#if HAVE_PCAP
		case PCAPINT:
		case PCAP:
                        ethptr = (packet->buffer + sizeof(struct pcap_pkthdr));
                        break;
#endif
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
			fprintf(stderr,"Don't know this trace format\n");
			assert(0);
        }
        return ethptr;
}

/** get a pointer to the IP header (if any)
 * @param packet	a pointer to a libtrace_packet structure
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
		case TRACE_TYPE_NONE:
			ipptr = trace_get_link(packet);
			break;
		case TRACE_TYPE_LINUX_SLL:
			{
				struct trace_sll_header_t *sll;

				sll = trace_get_link(packet);
				if (ntohs(sll->protocol)!=0x0800) {
					ipptr = NULL;
				}
				else {
					ipptr = ((void*)sll)+sizeof(*sll);
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
struct libtrace_tcp *trace_get_tcp(struct libtrace_packet_t *packet) {
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
struct libtrace_tcp *get_tcp_from_ip(struct libtrace_ip *ip, int *skipped)
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
struct libtrace_udp *trace_get_udp(struct libtrace_packet_t *packet) {
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
struct libtrace_udp *get_udp_from_ip(struct libtrace_ip *ip, int *skipped)
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
struct libtrace_icmp *trace_get_icmp(struct libtrace_packet_t *packet) {
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
#if HAVE_PCAP
		case PCAPINT:
                case PCAP:
                        pcapptr = (struct pcap_pkthdr *)packet->buffer;
			timestamp = ((((uint64_t)pcapptr->ts.tv_sec) << 32) + \
				(pcapptr->ts.tv_usec*UINT_MAX/1000000));
                        break;
#endif
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
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns time that this packet was seen in a struct timeval
 * @author Daniel Lawson
 * @author Perry Lorier
 */ 
struct timeval trace_get_timeval(const struct libtrace_packet_t *packet) {
        struct timeval tv;
#if HAVE_PCAP
        struct pcap_pkthdr *pcapptr = 0;
#endif
	uint64_t ts;
	//uint32_t seconds;
        switch (packet->trace->format) {
#if HAVE_PCAP
		case PCAPINT:
                case PCAP:
                        pcapptr = (struct pcap_pkthdr *)packet->buffer;
                        tv = pcapptr->ts;
                        break;
#endif
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
 * @param packet 	a pointer to a libtrace_packet structure
 * @returns time that this packet was seen in 64bit floating point seconds
 * @author Perry Lorier
 */ 
double trace_get_seconds(const struct libtrace_packet_t *packet) {
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
int trace_get_capture_length(const struct libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
#if HAVE_PCAP
	struct pcap_pkthdr *pcapptr = 0;
#endif
	struct wag_event_t *wag_event;
	switch (packet->trace->format) {
		case DAG:
		case ERF:
		case RTCLIENT:
			erfptr = (dag_record_t *)packet->buffer;
			return ntohs(erfptr->rlen);
#if HAVE_PCAP
		case PCAPINT:
		case PCAP:
			pcapptr = (struct pcap_pkthdr *)packet->buffer;
			//return ntohs(pcapptr->caplen);
			return pcapptr->caplen;
#endif
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
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns the size of the packet as it was on the wire.
 * @author Perry Lorier
 * @author Daniel Lawson
 * @note Due to the trace being a header capture, or anonymisation this may
 * not be the same as the Capture Len.
 */ 
int trace_get_wire_length(const struct libtrace_packet_t *packet){
	dag_record_t *erfptr = 0;
#if HAVE_PCAP
	struct pcap_pkthdr *pcapptr = 0;
#endif
	struct wag_event_t *wag_event = 0;
	switch (packet->trace->format) {
		case DAG:
		case ERF:
		case RTCLIENT:
			erfptr = (dag_record_t *)packet->buffer;
			return ntohs(erfptr->wlen);
			break;
#if HAVE_PCAP
		case PCAPINT:
		case PCAP:
			pcapptr = (struct pcap_pkthdr *)packet->buffer;
			return ntohs(pcapptr->len);
		 	break;
#endif
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
 * @param packet 	a pointer to a libtrace_packet structure
 * @returns libtrace_linktype_t
 * @author Perry Lorier
 * @author Daniel Lawson
 */
libtrace_linktype_t trace_get_link_type(const struct libtrace_packet_t *packet ) {
	dag_record_t *erfptr = 0;
#if HAVE_PCAP
	struct pcap_pkthdr *pcapptr = 0;
#endif
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
#if HAVE_PCAP
		case PCAPINT:
		case PCAP:
			pcapptr = (struct pcap_pkthdr *)packet->buffer;
			linktype = pcap_datalink(packet->trace->input.pcap);
			switch (linktype) {
				case DLT_NULL:
					return TRACE_TYPE_NONE;
				case DLT_EN10MB:
					return TRACE_TYPE_ETH; 
				case DLT_ATM_RFC1483:
					return TRACE_TYPE_ATM;
				case DLT_IEEE802_11:
					return TRACE_TYPE_80211;
#ifdef DLT_LINUX_SLL
				case DLT_LINUX_SLL:
					return TRACE_TYPE_LINUX_SLL;
#endif
			}
		 	break;
#endif
		case WAGINT:
		case WAG:
			return TRACE_TYPE_80211;
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
					trace_read_packet(trace,packet);
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
					trace_read_packet(trace,packet);
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
				/* "Prime" the pump */
				if (!trace->packet.buffer) {
					trace->packet.buffer = malloc(4096);
					trace->packet.size=
						trace_read_packet(trace,packet);
				}
				ts=trace_get_seconds(packet);
				if (trace->last_ts!=0) {
					event.seconds = ts - trace->last_ts;
					if (event.seconds>time(NULL)-trace->start_ts) {
						event.type = TRACE_EVENT_SLEEP;
						return event;
					}
					
				}
				else {
					trace->start_ts = time(NULL);
					trace->last_ts = ts;
				}

				packet->size = trace->packet.size;
				memcpy(packet->buffer,trace->packet.buffer,trace->packet.size);

				free(trace->packet.buffer);
				trace->packet.buffer = 0;
				event.type = TRACE_EVENT_PACKET;
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
			struct libtrace_packet_t *packet) {
#if HAVE_BPF
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
	
	dag_record_t *erfptr = 0;
	assert(packet);

	switch(packet->trace->format) {
		case DAG:
		case ERF:
		case RTCLIENT:
			erfptr = (dag_record_t *)packet->buffer;
			erfptr->flags.iface = direction;
			break;
		default:
			direction = -1;
	}
	
	return direction;
	
	
}

/** Get the direction flag, if it has one
 * @param packet a pointer to a libtrace_packet structure
 * @returns a signed value containing the direction flag, or -1 if this is not supported
 * @author Daniel Lawson
 */
int8_t trace_get_direction(const struct libtrace_packet_t *packet) {
	
	int8_t direction;
	dag_record_t *erfptr = 0;
	assert(packet);
	direction = -1;

	switch(packet->trace->format) {
		case DAG:
		case ERF:
		case RTCLIENT:
			erfptr = (dag_record_t *)packet->buffer;
			direction = erfptr->flags.iface;
			break;
		case PCAP:
			switch (trace_get_link_type(packet)) {
				case TRACE_TYPE_LINUX_SLL:
					{
						struct trace_sll_header_t *sll;
						sll = trace_get_link(packet);
						/* 0 == LINUX_SLL_HOST */
						if (sll->pkttype==0) {
							direction = 0;
						}
						else {
							direction = 1;
						}
						break;
					}
				default:
					/* pass */
			}
		default:
			/* pass */
	}
	
	return direction;
	
	
}

#define ROOT_SERVER(x) ((x) < 512)
#define ROOT_CLIENT(x) ((512 <= (x)) && ((x) < 1024))
#define NONROOT_SERVER(x) ((x) >= 5000)
#define NONROOT_CLIENT(x) ((1024 <= (x)) && ((x) < 5000))
#define DYNAMIC(x) ((49152 < (x)) && ((x) < 65535))
#define SERVER(x) ROOT_SERVER(x) || NONROOT_SERVER(x)
#define CLIENT(x) ROOT_CLIENT(x) || NONROOT_CLIENT(x) 


/** Attempt to deduce the 'server' port
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
	switch (packet->trace->format) {
#if HAVE_PCAP
		case PCAPINT:
		case PCAP:
			pcaphdr = (struct pcap_pkthdr *)packet->buffer;
			pcaphdr->caplen = size + sizeof(struct pcap_pkthdr);
			packet->size = pcaphdr->caplen;
			break;
#endif
		case ERF:
		case DAG:
		case RTCLIENT:
			erfptr = (dag_record_t *)packet->buffer;
			erfptr->rlen = ntohs(size + sizeof(dag_record_t));
			packet->size = size + sizeof(dag_record_t);
			break;
		case WAGINT:
		case WAG:
			// don't know how to do this?
			break;
	}
	return packet->size;
}

