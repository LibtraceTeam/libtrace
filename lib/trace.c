/** @file 
 *
 * @brief Trace file processing library
 *
 * @author Daniel Lawson
 * @author Perry Lorier
 *
 */
// $Id$
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>

#include "libtrace.h"
#include "fifo.h"

#include <net/bpf.h>
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

static int init_trace(struct libtrace_t **libtrace, char *uri) {
        char *scan = calloc(sizeof(char),16);
        char *uridata;
        
        // parse the URI to determine what sort of event we are dealing with
       
        // want snippet before the : to get the uri base type.

        if((uridata = strchr(uri,':')) == NULL) {
                // badly formed URI
                return 0;
        }

        if ((*uridata - *uri) > 16) {
                // badly formed URI
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
                         * /path/to/socket
                         * /path/to/file
                         * /path/to/file.gz
			 * /dev/device
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
                                        strndup(uridata,(scan - uridata));
                                        
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
 *  - erf:/path/to/erf/file
 *  - erf:/path/to/erf/file.gz
 *  - erf:/path/to/rtclient/socket
 *  - erf:-  (stdin)
 *  - dag:/dev/dagcard  		(not implementd)
 *  - pcap:pcapinterface 		(eg: pcap:eth0)
 *  - pcap:/path/to/pcap/file
 *  - pcap:/path/to/pcap/file.gz
 *  - pcap:/path/to/pcap/socket		(not implemented)
 *  - pcap:-
 *  - rtclient:hostname
 *  - rtclient:hostname:port
 *  - wag:/path/to/wag/file
 *  - wag:/path/to/wag/file.gz
 *  - wag:/path/to/wag/socket
 *  - wag:/dev/device
 *
 *  If an error occured why attempting to open the trace file, NULL is returned
 *  and an error is output to stdout.
 */
struct libtrace_t *create_trace(char *uri) {
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
                                libtrace->input.pcap = pcap_open_offline(libtrace->conn_info.path, errbuf); 
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
void destroy_trace(struct libtrace_t *libtrace) {
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

static int libtrace_read(struct libtrace_t *libtrace, void *buffer, size_t len) {
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
 * @param libtrace 	the trace to read from
 * @param buffer	the buffer to read into
 * @param len		the length of the buffer
 * @returns number of bytes copied.
 *
 * @note the buffer must be at least as large as the largest packet (plus
 * link layer, and trace packet metadata overhead)
 */
int libtrace_read_packet(struct libtrace_t *libtrace, void *buffer, size_t len, int *status) {
        int numbytes;
        int size;
        char buf[4096];
        struct pcap_pkthdr pcaphdr;
        const u_char *pcappkt;
	int read_required = 0;
	if (!libtrace) {
		fprintf(stderr,"Oi! You called libtrace_read_packet() with a NULL libtrace parameter!\n");
	}
        assert(libtrace);
        assert(buffer);
        assert(status);
        assert(len > 104); // we know we see packets this big anyway. Don't be silly.

	bzero(buffer,len);
        
        if (libtrace->format == PCAP || libtrace->format == PCAPINT) {
                if ((pcappkt = pcap_next(libtrace->input.pcap, &pcaphdr)) == NULL) {
                        return -1;
                }
                memcpy(buffer,&pcaphdr,sizeof(struct pcap_pkthdr));
                memcpy(buffer + sizeof(struct pcap_pkthdr),pcappkt,pcaphdr.len);
                numbytes = pcaphdr.len;

		return numbytes;
        } 

	do {
		if (fifo_out_available(libtrace->fifo) == 0 || read_required) {
			if ((numbytes = libtrace_read(libtrace,buf,4096))<=0){
				return numbytes; 
			}
			fifo_write(libtrace->fifo,buf,numbytes);

			read_required = 0;
		}

		switch (libtrace->format) {
			case RTCLIENT:
				// only do this if we're reading from the RT interface
				if (fifo_out_read(libtrace->fifo, status, sizeof(int)) == 0) {
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

		assert(len > size);

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
		
        	return numbytes;

	} while (1);
}


/** get a pointer to the link layer
 * @param libtrace	a pointer to the trace object returned from gettrace
 * @param buffer	a pointer to a filled in buffer
 * @param buflen	a pointer to the size of the buffer
 *
 * @returns a pointer to the link layer, or NULL if there is no link layer
 * you should call get_link_type() to find out what type of link layer this is
 */
void *get_link(struct libtrace_t *libtrace, void *buffer, int buflen) {
        void *ethptr = 0;
	struct wag_event_t *event = buffer;
	struct wag_data_event_t *data_event;
        
        switch(libtrace->format) {
                case ERF:
                case DAG:
                case RTCLIENT:
			// DAG people are insane, deal with ethernet having
			// some extra padding and crap
			if (get_link_type(libtrace,buffer,buflen)==TRACE_TYPE_ETH) 
                        	ethptr = ((uint8_t *)buffer + 16 + 2);
			else
				ethptr = ((uint8_t *)buffer + 16 + 2);
                        break;
		case PCAPINT:
		case PCAP:
                        ethptr = (struct ether_header *)(buffer + sizeof(struct pcap_pkthdr));
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
struct libtrace_ip *get_ip(struct libtrace_t *libtrace, void *buffer, int buflen) {
        struct libtrace_ip *ipptr = 0;

	switch(get_link_type(libtrace,buffer,buflen)) {
		case TRACE_TYPE_80211:
			{ 
				
				struct ieee_802_11_header *wifi = get_link(libtrace, buffer, buflen);	

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
				struct ether_header *eth = get_link(libtrace,
						buffer, buflen);
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
				struct atm_rec *atm = get_link(libtrace,
						buffer, buflen);
				// TODO: Find out what ATM does, and return
				//       NULL for non IP data
				//       Presumably it uses the normal stuff
				ipptr =  (void*)&atm->pload;
				break;
			}
		default:
			fprintf(stderr,"Don't understand link layer type %i in get_ip()\n",
				get_link_type(libtrace,buffer,buflen));
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
struct libtrace_tcp *get_tcp(struct libtrace_t *libtrace, void *buffer, int buflen) {
        struct libtrace_tcp *tcpptr = 0;
        struct libtrace_ip *ipptr = 0;

        if(!(ipptr = get_ip(libtrace,buffer,buflen))) {
                return 0;
        }
        if (ipptr->ip_p == 6) {
                tcpptr = (struct libtrace_tcp *)((int)ipptr + (ipptr->ip_hl * 4));
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
struct libtrace_udp *get_udp(struct libtrace_t *libtrace, void *buffer, int buflen) {
        struct libtrace_udp *udpptr = 0;
        struct libtrace_ip *ipptr = 0;
        
        if(!(ipptr = get_ip(libtrace,buffer,buflen))) {
                return 0;
        }
        if (ipptr->ip_p == 17) {
                udpptr = (struct libtrace_udp *)((int)ipptr + (ipptr->ip_hl * 4));
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
struct libtrace_icmp *get_icmp(struct libtrace_t *libtrace, void *buffer, int buflen) {
        struct libtrace_icmp *icmpptr = 0;
        struct libtrace_ip *ipptr = 0;
        
        if(!(ipptr = get_ip(libtrace,buffer,buflen))) {
                return 0;
        }
        if (ipptr->ip_p == 1) {
                icmpptr = (struct libtrace_icmp *)((int)ipptr + (ipptr->ip_hl * 4));
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
uint64_t get_erf_timestamp(struct libtrace_t *libtrace, void *buffer, int buflen) {
	uint64_t timestamp = 0;
        dag_record_t *erfptr = 0;
        struct pcap_pkthdr *pcapptr = 0;
	struct wag_event_t *wagptr = 0;
        switch (libtrace->format) {
                case DAG:
                case ERF:
                case RTCLIENT:
                        erfptr = (dag_record_t *)buffer;
			timestamp = erfptr->ts;
                        break;
		case PCAPINT:
                case PCAP:
                        pcapptr = (struct pcap_pkthdr *)buffer;
			timestamp = ((((uint64_t)pcapptr->ts.tv_sec) << 32) + \
				(pcapptr->ts.tv_usec*UINT_MAX/1000000));
                        break;
		case WAGINT:
		case WAG:
			wagptr = buffer;
			timestamp = wagptr->timestamp_lo;
			timestamp |= (uint64_t)wagptr->timestamp_hi<<32;
			timestamp = ((timestamp%44000000)*(UINT_MAX/44000000))
				  | ((timestamp/44000000)<<32);
			break;
		default:
			fprintf(stderr,"Unknown format in get_erf_timestamp\n");
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
struct timeval get_timeval(struct libtrace_t *libtrace, void *buffer, int buflen) {
        struct timeval tv;
        struct pcap_pkthdr *pcapptr = 0;
	uint64_t ts;
	//uint32_t seconds;
        switch (libtrace->format) {
		case PCAPINT:
                case PCAP:
                        pcapptr = (struct pcap_pkthdr *)buffer;
                        tv = pcapptr->ts;
                        break;
		case WAGINT:
		case WAG:
                case DAG:
                case ERF:
                case RTCLIENT:
		default:
			// FIXME: This isn't portable to big-endian machines
			ts = get_erf_timestamp(libtrace,buffer,buflen);
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
double get_seconds(struct libtrace_t *libtrace, void *buffer, int buflen) {
	uint64_t ts;
	ts = get_erf_timestamp(libtrace,buffer,buflen);
	return (ts>>32) + ((ts & UINT_MAX)*1.0 / UINT_MAX);
}

/** Get the size of the packet in the trace
 * @param libtrace the libtrace opaque pointer
 * @param buffer a pointer to a filled in buffer
 * @param buflen the length of the buffer
 * @returns the size of the packet in the trace
 * @author Perry Lorier
 * @note Due to this being a header capture, or anonymisation, this may not
 * be the same size as the original packet.  See get_wire_length() for the 
 * original size of the packet.
 * @note This can (and often is) different for different packets in a trace!
 * @par 
 *  This is sometimes called the "snaplen".
 */ 
int get_capture_length(struct libtrace_t *libtrace, void *buffer, int buflen) {
	dag_record_t *erfptr = 0;
	struct pcap_pkthdr *pcapptr = 0;
	struct wag_event_t *wag_event;
	switch (libtrace->format) {
		case DAG:
		case ERF:
		case RTCLIENT:
			erfptr = (dag_record_t *)buffer;
			return ntohs(erfptr->rlen);
		case PCAPINT:
		case PCAP:
			pcapptr = (struct pcap_pkthdr *)buffer;
			return ntohs(pcapptr->caplen);
		case WAGINT:
		case WAG:
			wag_event = buffer;
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
int get_wire_length(struct libtrace_t *libtrace, void *buffer, int buflen){
	dag_record_t *erfptr = 0;
	struct pcap_pkthdr *pcapptr = 0;
	struct wag_event_t *wag_event = 0;
	switch (libtrace->format) {
		case DAG:
		case ERF:
		case RTCLIENT:
			erfptr = (dag_record_t *)buffer;
			return ntohs(erfptr->wlen);
			break;
		case PCAPINT:
		case PCAP:
			pcapptr = (struct pcap_pkthdr *)buffer;
			return ntohs(pcapptr->len);
		 	break;
		case WAGINT:
		case WAG:
			wag_event = buffer;
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
libtrace_linktype_t get_link_type(
		struct libtrace_t *libtrace, 
		void *buffer, 
		int buflen) {
	dag_record_t *erfptr = 0;
	struct pcap_pkthdr *pcapptr = 0;
	int linktype = 0;
	switch (libtrace->format) {
		case DAG:
		case ERF:
		case RTCLIENT:
			erfptr = (dag_record_t *)buffer;
			switch (erfptr->type) {
				case TYPE_ETH: return TRACE_TYPE_ETH;
				case TYPE_ATM: return TRACE_TYPE_ATM;
				default: assert(0);
			}
			return erfptr->type;
			
			break;
		case PCAPINT:
		case PCAP:
			pcapptr = (struct pcap_pkthdr *)buffer;
			linktype = pcap_datalink(libtrace->input.pcap);
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
uint8_t *get_source_mac(struct libtrace_t *libtrace,
		void *buffer,
		int buflen) {
	void *link = get_link(libtrace,buffer,buflen);
	struct ieee_802_11_header *wifi = link;
        struct ether_header *ethptr = link;
	if (!link)
		return NULL;
	switch (get_link_type(libtrace,buffer,buflen)) {
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
uint8_t *get_destination_mac(struct libtrace_t *libtrace,
		void *buffer,
		int buflen) {
	void *link = get_link(libtrace,buffer,buflen);
	struct ieee_802_11_header *wifi = link;
        struct ether_header *ethptr = link;
	if (!link)
		return NULL;
	switch (get_link_type(libtrace,buffer,buflen)) {
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
 * @returns
 *  TRACE_EVENT_IOWAIT	Waiting on I/O on <fd>
 *  TRACE_EVENT_SLEEP	Next event in <seconds>
 *  TRACE_EVENT_PACKET	Packet arrived in <buffer> with size <size>
 */
libtrace_event_t libtrace_event(struct libtrace_t *trace,
			int *fd,double *seconds,
			void *buffer, int *size)
{
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
				int status;
				double ts;
				/* "Prime" the pump */
				if (!trace->packet.buffer) {
					trace->packet.buffer = malloc(4096);
					trace->packet.size=libtrace_read_packet(trace,
							trace->packet.buffer,
							4096,
							&status);
				}
				ts=get_seconds(trace,
					trace->packet.buffer,
					trace->packet.size);
				if (trace->last_ts!=0) {
					*seconds = ts - trace->last_ts;
					if (*seconds>time(NULL)-trace->start_ts)
						return TRACE_EVENT_SLEEP;
				}
				else {
					trace->start_ts = time(NULL);
					trace->last_ts = ts;
				}

				*size = trace->packet.size;
				memcpy(buffer,trace->packet.buffer,*size);

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
struct libtrace_filter_t *libtrace_bpf_setfilter(const char *filterstring) {
	struct libtrace_filter_t *filter = malloc(sizeof(struct libtrace_filter_t));
	filter->filterstring = strdup(filterstring);
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
int libtrace_bpf_filter(struct libtrace_t *trace, 
			struct libtrace_filter_t *filter,
			void *buffer, 
			int buflen) {
	
	int linktype = get_link_type(trace,buffer,buflen);
	void *linkptr = get_link(trace,buffer,buflen);	
	int clen = get_capture_length(trace,buffer,buflen);
	assert(trace);
	assert(filter);
	assert(buffer);
	

	if (filter->filterstring && ! filter->filter) {
		pcap_t *pcap;
		struct bpf_program bpfprog;

		switch (linktype) {
			case TYPE_ETH:
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

	return bpf_filter(filter->filter, linkptr, clen, clen);
}


