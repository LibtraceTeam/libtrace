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

#ifndef LIBTRACE_H
#define LIBTRACE_H

#include <sys/types.h>
#include <netinet/in.h>

#ifdef __cplusplus 
extern "C" { 
#endif
/** @file
 *
 * @brief Trace file processing library header
 *
 * @author Daniel Lawson
 * @author Perry Lorier
 *
 * @version $Id$
 *
 * This library provides a per packet interface into a trace file, or a live 
 * captures.  It supports ERF, DAG cards, WAG cards, WAG's event format,
 * pcap etc.
 *
 * @par Usage
 * <ol>
 * <li> include "libtrace.h" 
 * <li> call create_trace with the uri of the trace you're interested in.<br>
 * This is usually passed in as argv[1] to your program.
 * <li> call libtrace_read_packet(), passing in the libtrace_t returned from
 * create trace and a buffer (and the buffer length)
 * <li> call getIP() on the buffer, and do whatever you need
 * <li> loop back to step 3, until libtrace_read_packet() returns -1
 * </ol>
 * @par Linking
 * To use this library you need to link against libtrace by passing -ltrace
 * to your linker. You may also need to link against a version of libpcap 
 * and of zlib which are compiled for largefile support (if you wish to access
 * traces larger than 2 GB). This is left as an exercise for the reader. Debian
 * Woody, at least, does not support large file offsets.
 *
 */

#define COLLECTOR_PORT 3435

/** Opaque structure holding information about a trace */
struct libtrace_t;
        
/** Opaque structure holding information about a bpf filter */
struct libtrace_filter_t;

/** Opaque structure holding information about a packet */
#define LIBTRACE_PACKET_BUFSIZE 65536
struct libtrace_packet_t {
	struct libtrace_t *trace;
	char buffer[LIBTRACE_PACKET_BUFSIZE];
	size_t size;
	uint8_t status;
};

/** Structure for dealing with IP packets */
struct libtrace_ip
  {
#if BYTE_ORDER == LITTLE_ENDIAN
    unsigned int ip_hl:4;		/**< header length */
    unsigned int ip_v:4;		/**< version */
#elif BYTE_ORDER == BIG_ENDIAN
    unsigned int ip_v:4;		/**< version */
    unsigned int ip_hl:4;		/**< header length */
#else
#   error "Adjust your <bits/endian.h> defines"
#endif
    u_int8_t ip_tos;			/**< type of service */
    u_short ip_len;			/**< total length */
    u_short ip_id;			/**< identification */
    u_short ip_off;			/**< fragment offset field */
#define	IP_RF 0x8000			/**< reserved fragment flag */
#define	IP_DF 0x4000			/**< dont fragment flag */
#define	IP_MF 0x2000			/**< more fragments flag */
#define	IP_OFFMASK 0x1fff		/**< mask for fragmenting bits */
    u_int8_t ip_ttl;			/**< time to live */
    u_int8_t ip_p;			/**< protocol */
    u_short ip_sum;			/**< checksum */
    struct in_addr ip_src;		/**< source address */
    struct in_addr ip_dst;		/**< dest address */
  };

/** Structure for dealing with TCP packets */
struct libtrace_tcp
  {
    u_int16_t source;		/**< Source Port */
    u_int16_t dest;		/**< Destination port */
    u_int32_t seq;		/**< Sequence number */
    u_int32_t ack_seq;		/**< Acknowledgement Number */
#  if BYTE_ORDER == LITTLE_ENDIAN
    u_int16_t res1:4;		/**< Reserved bits */
    u_int16_t doff:4;		
    u_int16_t fin:1;		/**< FIN */
    u_int16_t syn:1;		/**< SYN flag */
    u_int16_t rst:1;		/**< RST flag */
    u_int16_t psh:1;		/**< PuSH flag */
    u_int16_t ack:1;		/**< ACK flag */
    u_int16_t urg:1;		/**< URG flag */
    u_int16_t res2:2;		/**< Reserved */
#  elif BYTE_ORDER == BIG_ENDIAN
    u_int16_t doff:4;		
    u_int16_t res1:4;		/**< Reserved bits */
    u_int16_t res2:2;		/**< Reserved */
    u_int16_t urg:1;		/**< URG flag */
    u_int16_t ack:1;		/**< ACK flag */
    u_int16_t psh:1;		/**< PuSH flag */
    u_int16_t rst:1;		/**< RST flag */
    u_int16_t syn:1;		/**< SYN flag */
    u_int16_t fin:1;		/**< FIN flag */
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    u_int16_t window;		/**< Window Size */
    u_int16_t check;		/**< Checksum */
    u_int16_t urg_ptr;		/**< Urgent Pointer */
};

/** UDP Header for dealing with UDP packets */
struct libtrace_udp {
  u_int16_t	source;		/**< Source port */
  u_int16_t	dest;		/**< Destination port */
  u_int16_t	len;		/**< Length */
  u_int16_t	check;		/**< Checksum */
};

/** ICMP Header for dealing with icmp packets */
struct libtrace_icmp
{
  u_int8_t type;		/**< message type */
  u_int8_t code;		/**< type sub-code */
  u_int16_t checksum;		/**< checksum */
  union
  {
    struct
    {
      u_int16_t	id;
      u_int16_t	sequence;
    } echo;			/**< echo datagram */
    u_int32_t	gateway;	/**< gateway address */
    struct
    {
      u_int16_t	unused;
      u_int16_t	mtu;
    } frag;			/**< path mtu discovery */
  } un;
};




/** Create a trace file from a URI
 * 
 * @returns opaque pointer to a libtrace_t
 *
 * Valid URI's are:
 *  - erf:/path/to/erf/file
 *  - erf:/path/to/erf/file.gz
 *  - erf:/path/to/rtclient/socket
 *  - erf:-  (stdin)
 *  - dag:/dev/dagcard                  (implementd?)
 *  - pcap:pcapinterface                (eg: pcap:eth0)
 *  - pcap:/path/to/pcap/file
 *  - pcap:/path/to/pcap/file.gz
 *  - pcap:/path/to/pcap/socket         (implemented?)
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
struct libtrace_t *trace_create(char *uri);

/** Close a trace file, freeing up any resources it may have been using
 *
 */
void trace_destroy(struct libtrace_t *trace);

/** Read one packet from the trace into buffer
 *
 * @param libtrace 	the libtrace opaque pointer
 * @param packet  	the packet opaque pointer
 * @returns false if it failed to read a packet
 *
 */
int trace_read_packet(struct libtrace_t *trace, struct libtrace_packet_t *packet);

/** get a pointer to the link layer
 * @param packet  	the packet opaque pointer
 *
 * @returns a pointer to the link layer, or NULL if there is no link layer
 *
 * @note you should call getLinkType() to find out what type of link layer 
 * this is
 */
void *trace_get_link(struct libtrace_packet_t *packet);

/** get a pointer to the IP header (if any)
 * @param packet  	the packet opaque pointer
 *
 * @returns a pointer to the IP header, or NULL if there is not an IP packet
 */
struct libtrace_ip *trace_get_ip(struct libtrace_packet_t *packet);

/** get a pointer to the TCP header (if any)
 * @param packet  	the packet opaque pointer
 *
 * @returns a pointer to the TCP header, or NULL if there is not a TCP packet
 */
struct libtrace_tcp *trace_get_tcp(struct libtrace_packet_t *packet);

/** get a pointer to the UDP header (if any)
 * @param packet  	the packet opaque pointer
 *
 * @returns a pointer to the UDP header, or NULL if this is not a UDP packet
 */
struct libtrace_udp *trace_get_udp(struct libtrace_packet_t *packet);

/** get a pointer to the ICMP header (if any)
 * @param packet  	the packet opaque pointer
 *
 * @returns a pointer to the ICMP header, or NULL if this is not a ICMP packet
 */
struct libtrace_icmp *trace_get_icmp(struct libtrace_packet_t *packet);

/** Get the current time in DAG time format 
 * @param packet  	the packet opaque pointer
 *
 * @returns a 64 bit timestamp in DAG ERF format (upper 32 bits are the seconds
 * past 1970-01-01, the lower 32bits are partial seconds)
 * @author Daniel Lawson
 */
uint64_t trace_get_erf_timestamp(struct libtrace_packet_t *packet);

/** Get the current time in struct timeval
 * @param packet  	the packet opaque pointer
 *
 * @returns time that this packet was seen in a struct timeval
 * @author Daniel Lawson
 * @author Perry Lorier
 */ 
struct timeval trace_get_timeval(struct libtrace_packet_t *packet);

/** Get the current time in floating point seconds
 * @param packet  	the packet opaque pointer
 *
 * @returns time that this packet was seen in 64bit floating point seconds
 * @author Perry Lorier
 */
double trace_get_seconds(struct libtrace_packet_t *packet);

/** Get the size of the packet in the trace
 * @param packet  	the packet opaque pointer
 * @returns the size of the packet in the trace
 * @author Perry Lorier
 * @note Due to this being a header capture, or anonymisation, this may not
 * be the same size as the original packet.  See get_wire_length() for the original
 * size of the packet.
 * @note This can (and often is) different for different packets in a trace!
 * @par 
 *  This is sometimes called the "snaplen".
 */

int trace_get_capture_length(struct libtrace_packet_t *packet);

/** Get the size of the packet as it was seen on the wire.
 * @param packet  	the packet opaque pointer
 * @returns the size of the packet as it was on the wire.
 * @author Perry Lorier
 * @author Daniel Lawson
 * @note Due to the trace being a header capture, or anonymisation this may
 * not be the same as the Capture Len.
 */ 

int trace_get_wire_length(struct libtrace_packet_t *packet);

/** Link layer types
 */
typedef enum { 
       TRACE_TYPE_LEGACY, 
       TRACE_TYPE_HDLC_POS, 
       TRACE_TYPE_ETH,
       TRACE_TYPE_ATM,
       TRACE_TYPE_80211,
     } libtrace_linktype_t;

/** Get the type of the link layer
 * @param packet  	the packet opaque pointer
 * @returns libtrace_linktype_t
 * @author Perry Lorier
 * @author Daniel Lawson
 */

inline libtrace_linktype_t trace_get_link_type(struct libtrace_packet_t *packet);

/** Get the destination MAC addres
 * @param packet  	the packet opaque pointer
 * @returns a pointer to the destination mac, (or NULL if there is no 
 * destination MAC)
 * @author Perry Lorier
 */
uint8_t *trace_get_destination_mac(struct libtrace_packet_t *packet);

/** Get the source MAC addres
 * @param packet  	the packet opaque pointer
 * @returns a pointer to the source mac, (or NULL if there is no source MAC)
 * @author Perry Lorier
 */
uint8_t *trace_get_source_mac(struct libtrace_packet_t *packet);

/** Get the direction flag, if it has one
 * @param packet  	the packet opaque pointer
 * @returns a signed value containing the direction flag, or -1 if this is not supported
 * @author Daniel Lawson
 */
int8_t trace_get_direction(struct libtrace_packet_t *packet);

/** Event types */
typedef enum {
	TRACE_EVENT_IOWAIT,
	TRACE_EVENT_SLEEP,
	TRACE_EVENT_PACKET
} libtrace_event_t;

typedef struct {
	libtrace_event_t type;
	int fd;
	double seconds;
} libtrace_eventobj_t;

/** process a libtrace event
 * @param trace the libtrace opaque pointer
 * @param packet the libtrace_packet opaque pointer
 * @param fd a pointer to a file descriptor to listen on
 * @param seconds a pointer the time in seconds since to the next event
 * @returns libtrace_event struct containing the type, and potential
 * 	fd or seconds to sleep on
 *
 * Type can be:
 *  TRACE_EVENT_IOWAIT	Waiting on I/O on <fd>
 *  TRACE_EVENT_SLEEP	Next event in <seconds>
 *  TRACE_EVENT_PACKET	Packet arrived in <buffer> with size <size>
 */
libtrace_eventobj_t trace_event(struct libtrace_t *trace,
		struct libtrace_packet_t *packet);

/** setup a BPF filter
 * @param filterstring a char * containing the bpf filter string
 * @returns opaque pointer pointer to a libtrace_filter_t object
 * @author Daniel Lawson
 */
struct libtrace_filter_t *trace_bpf_setfilter(const char *filterstring);

/** apply a BPF filter
 * @param filter 	the filter opaque pointer
 * @param packet	the packet opaque pointer
 * @returns the return value from bpf_filter
 * @author Daniel Lawson
 */
int trace_bpf_filter(struct libtrace_filter_t *filter,
		struct libtrace_packet_t *packet);


typedef enum {USE_DEST, USE_SOURCE} serverport_t;

/** hint at the server port in specified protocol
 * @param protocol	the IP layer protocol, eg 6 (tcp), 17 (udp)
 * @param source	the source port from the packet
 * @param dest		the destination port from the packet
 * @returns one of USE_SOURCE or USE_DEST depending on which one you should use
 * @author Daniel Lawson
 */
int8_t trace_get_server_port(uint8_t protocol, uint16_t source, uint16_t dest);

#ifdef __cplusplus
} // extern "C"
#endif // #ifdef __cplusplus
#endif // LIBTRACE_H_
