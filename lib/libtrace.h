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
 * See the example/ directory in the source distribution for some simple examples
 * @par Linking
 * To use this library you need to link against libtrace by passing -ltrace
 * to your linker. You may also need to link against a version of libpcap 
 * and of zlib which are compiled for largefile support (if you wish to access
 * traces larger than 2 GB). This is left as an exercise for the reader. Debian
 * Woody, at least, does not support large file offsets.
 *
 */

#include <sys/types.h>
#include <netinet/in.h>
/** API version as 2 byte hex digits, eg 0xXXYYZZ */
#define LIBTRACE_API_VERSION 0x030000  /* 3.0.00 */

#ifdef __cplusplus 
extern "C" { 
#endif

/* Function does not depend on anything but its
 * parameters, used to hint gcc's optimisations
 */
#if __GNUC__ >= 3 
#  define SIMPLE_FUNCTION __attribute__((pure))
#  define UNUSED __attribute__((unused))
#else
#  define SIMPLE_FUNCTION
#  define UNUSED
#endif
	
#define RT_DATA 1
#define RT_MSG 2

	
/** Opaque structure holding information about an output trace */
typedef struct libtrace_out_t libtrace_out_t;
	
/** Opaque structure holding information about a trace */
typedef struct libtrace_t libtrace_t;
        
/** Opaque structure holding information about a bpf filter */
typedef struct libtrace_filter_t libtrace_filter_t;

/** Structure holding status information for a packet */
typedef struct libtrace_packet_status {
	uint8_t type;
	uint8_t reserved;
	uint16_t message;

} libtrace_packet_status_t;

typedef enum {PACKET, EXTERNAL } buf_control_t;
/** Structure holding information about a packet */
#define LIBTRACE_PACKET_BUFSIZE 65536
typedef struct libtrace_packet_t {
	struct libtrace_t *trace;
	void *header;
	void *payload;
	void *buffer;
	size_t size;
	libtrace_packet_status_t status;
	buf_control_t buf_control; 
} __attribute__ ((packed)) libtrace_packet_t;
                     

/** Enumeration of error codes */
enum {E_NOERROR, E_BAD_FORMAT, E_NO_INIT, E_NO_INIT_OUT, E_URI_LONG, E_URI_NOCOLON, E_INIT_FAILED };

/** Structure for dealing with IP packets */
typedef struct libtrace_ip
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
} __attribute__ ((packed)) libtrace_ip_t
;

/** Structure for dealing with TCP packets */
typedef struct libtrace_tcp
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
} __attribute__ ((packed)) libtrace_tcp_t;

/** UDP Header for dealing with UDP packets */
typedef struct libtrace_udp {
  u_int16_t	source;		/**< Source port */
  u_int16_t	dest;		/**< Destination port */
  u_int16_t	len;		/**< Length */
  u_int16_t	check;		/**< Checksum */
} __attribute__ ((packed)) libtrace_udp_t;

/** ICMP Header for dealing with icmp packets */
typedef struct libtrace_icmp
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
  } un;				/**< Union for payloads of various icmp codes */
} __attribute__ ((packed)) libtrace_icmp_t;

/** LLC/SNAP header */
typedef struct libtrace_llcsnap
{
  u_int8_t dsap;
  u_int8_t ssap;
  u_int8_t control;
  u_int32_t oui:24;
  u_int16_t type;
} __attribute__ ((packed)) libtrace_llcsnap_t;

/** 802.3 frame */
typedef struct libtrace_ether
{
  u_int8_t ether_dhost[6];	/* destination ether addr */
  u_int8_t ether_shost[6];	/* source ether addr */
  u_int16_t ether_type;		/* packet type ID field (next-header) */
} __attribute__ ((packed)) libtrace_ether_t;

/** 802.1Q frame */
typedef struct libtrace_8021q 
{
  u_int8_t  ether_dhost[6];      /* destination eth addr */
  u_int8_t  ether_shost[6];      /* source ether addr    */
  u_int16_t ether_type;          /* packet type ID field , 0x8100 for VLAN */
  u_int16_t vlan_pri:3;		 /* vlan user priority */
  u_int16_t vlan_cfi:1;	 	 /* vlan format indicator, 0 for ethernet, 1 for token ring */
  u_int16_t vlan_id:12;	 	 /* vlan id */
  u_int16_t vlan_ether_type;	 /* vlan sub-packet type ID field (next-header)*/
} __attribute__ ((packed)) libtrace_8021q_t;

/** ATM cell */
typedef struct libtrace_atm_cell
{
  u_int8_t gfc:4;
  u_int8_t vpi;
  u_int16_t vci;
  u_int8_t pt:3;
  u_int8_t clp:1;
  u_int8_t hec;
} __attribute__ ((packed)) libtrace_atm_cell;

/** POS header */
typedef struct libtrace_pos
{
 u_int16_t header;
 u_int16_t ether_type;
} __attribute__ ((packed)) libtrace_pos;

/** Prints help information for libtrace 
 *
 * Function prints out some basic help information regarding libtrace,
 * and then prints out the help() function registered with each input module
 */
void trace_help();

/** Gets the output format for a given output trace
 *
 * @param libtrace	the output trace to get the name of the format fo
 * @returns callee-owned null-terminated char* containing the output format
 *
 */
SIMPLE_FUNCTION
char *trace_get_output_format(const struct libtrace_out_t *libtrace);

/** Prints error information
 *
 * Prints out a descriptive error message for the currently set trace_err value
 */
void trace_perror(const char *caller);

/** Create a trace file from a URI
 * 
 * @param uri containing a valid libtrace URI
 * @returns opaque pointer to a libtrace_t
 *
 * Valid URI's are:
 *  - erf:/path/to/erf/file
 *  - erf:/path/to/erf/file.gz
 *  - erf:/path/to/rtclient/socket
 *  - erf:-  (stdin)
 *  - dag:/dev/dagcard                  
 *  - pcapint:pcapinterface                (eg: pcap:eth0)
 *  - pcap:/path/to/pcap/file
 *  - pcap:-
 *  - rtclient:hostname
 *  - rtclient:hostname:port
 *  - wag:-
 *  - wag:/path/to/wag/file
 *  - wag:/path/to/wag/file.gz
 *  - wag:/path/to/wag/socket
 *
 *  If an error occured when attempting to open the trace file, NULL is returned
 *  and trace_errno is set. Use trace_perror() to get more information 
 */
struct libtrace_t *trace_create(const char *uri);

/** Creates a "dummy" trace file that has only the format type set.
 *
 * @returns opaque pointer to a (sparsely initialised) libtrace_t
 *
 * IMPORTANT: Do not attempt to call trace_read_packet or other such functions with
 * the dummy trace. Its intended purpose is to act as a packet->trace for libtrace_packet_t's
 * that are not associated with a libtrace_t structure.
 */
struct libtrace_t *trace_create_dead(const char *uri);

/** Creates a trace output file from a URI. 
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
struct libtrace_out_t *trace_output_create(const char *uri);

/** Parses an output options string and calls the appropriate function to deal with output options.
 *
 * @param libtrace	the output trace object to apply the options to
 * @param options	the options string
 * @returns -1 if option configuration failed, 0 otherwise
 *
 * @author Shane Alcock
 */
int trace_output_config(struct libtrace_out_t *libtrace, char *options);

/** Close a trace file, freeing up any resources it may have been using
 *
 */
void trace_destroy(struct libtrace_t *trace);

/** Close a trace file, freeing up any resources it may have been using
 * @param trace		trace file to be destroyed
 */
void trace_destroy_dead(struct libtrace_t *trace);

/** Close a trace output file, freeing up any resources it may have been using
 *
 * @param trace		the output trace file to be destroyed
 *
 * @author Shane Alcock
 */
void trace_output_destroy(struct libtrace_out_t *trace);

/** Create a new packet object
 *
 * @return a pointer to an initialised libtrace_packet_t object
 */
struct libtrace_packet_t *trace_packet_create();

/** Destroy a packet object
 *
 * sideeffect: sets packet to NULL
 */
void trace_packet_destroy(struct libtrace_packet_t **packet);


/** Read one packet from the trace into buffer
 *
 * @param trace 	the libtrace opaque pointer
 * @param packet  	the packet opaque pointer
 * @returns 0 on EOF, negative value on error
 *
 */
int trace_read_packet(struct libtrace_t *trace, struct libtrace_packet_t *packet);

/** Write one packet out to the output trace
 *
 * @param trace		the libtrace_out opaque pointer
 * @param packet	the packet opaque pointer
 * @returns the number of bytes written out, if zero or negative then an error has occured.
 */
int trace_write_packet(struct libtrace_out_t *trace, const struct libtrace_packet_t *packet);

/** get a pointer to the link layer
 * @param packet  	the packet opaque pointer
 *
 * @returns a pointer to the link layer, or NULL if there is no link layer
 *
 * @note you should call getLinkType() to find out what type of link layer 
 * this is
 */
SIMPLE_FUNCTION
void *trace_get_link(const struct libtrace_packet_t *packet);

/** get a pointer to the IP header (if any)
 * @param packet  	the packet opaque pointer
 *
 * @returns a pointer to the IP header, or NULL if there is not an IP packet
 */
SIMPLE_FUNCTION
struct libtrace_ip *trace_get_ip(const struct libtrace_packet_t *packet);

/** get a pointer to the TCP header (if any)
 * @param packet  	the packet opaque pointer
 *
 * @returns a pointer to the TCP header, or NULL if there is not a TCP packet
 */
SIMPLE_FUNCTION
struct libtrace_tcp *trace_get_tcp(const struct libtrace_packet_t *packet);

/** get a pointer to the TCP header (if any) given a pointer to the IP header
 * @param ip		The IP header
 * @param[out] skipped	An output variable of the number of bytes skipped
 *
 * @returns a pointer to the TCP header, or NULL if this is not a TCP packet
 *
 * Skipped can be NULL, in which case it will be ignored by the program.
 *
 * @author Perry Lorier
 */
SIMPLE_FUNCTION
struct libtrace_tcp *trace_get_tcp_from_ip(const struct libtrace_ip *ip,int *skipped);

/** get a pointer to the UDP header (if any)
 * @param packet  	the packet opaque pointer
 *
 * @returns a pointer to the UDP header, or NULL if this is not a UDP packet
 */
SIMPLE_FUNCTION
struct libtrace_udp *trace_get_udp(const struct libtrace_packet_t *packet);

/** get a pointer to the UDP header (if any) given a pointer to the IP header
 * @param 	ip	The IP header
 * @param[out] 	skipped	An output variable of the number of bytes skipped
 *
 * @returns a pointer to the UDP header, or NULL if this is not an UDP packet
 *
 * Skipped may be NULL, in which case it will be ignored by this function.
 */
SIMPLE_FUNCTION
struct libtrace_udp *trace_get_udp_from_ip(const struct libtrace_ip *ip,int *skipped);

/** get a pointer to the ICMP header (if any)
 * @param packet  	the packet opaque pointer
 *
 * @returns a pointer to the ICMP header, or NULL if this is not a ICMP packet
 */
SIMPLE_FUNCTION
struct libtrace_icmp *trace_get_icmp(const struct libtrace_packet_t *packet);

/** get a pointer to the ICMP header (if any) given a pointer to the IP header
 * @param ip		The IP header
 * @param[out] skipped	An output variable of the number of bytes skipped
 *
 * @returns a pointer to the ICMP header, or NULL if this is not an ICMP packet
 *
 * Skipped may be NULL, in which case it will be ignored by this function
 */
SIMPLE_FUNCTION
struct libtrace_icmp *trace_get_icmp_from_ip(const struct libtrace_ip *ip,int *skipped);

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
 */
int trace_get_next_option(unsigned char **ptr,int *len,
			unsigned char *type,
			unsigned char *optlen,
			unsigned char **data);


/** Get the current time in DAG time format 
 * @param packet  	the packet opaque pointer
 *
 * @returns a 64 bit timestamp in DAG ERF format (upper 32 bits are the seconds
 * past 1970-01-01, the lower 32bits are partial seconds)
 * @author Daniel Lawson
 */
SIMPLE_FUNCTION
uint64_t trace_get_erf_timestamp(const struct libtrace_packet_t *packet);

/** Get the current time in struct timeval
 * @param packet  	the packet opaque pointer
 *
 * @returns time that this packet was seen in a struct timeval
 * @author Daniel Lawson
 * @author Perry Lorier
 */ 
SIMPLE_FUNCTION
struct timeval trace_get_timeval(const struct libtrace_packet_t *packet);

/** Get the current time in floating point seconds
 * @param packet  	the packet opaque pointer
 *
 * @returns time that this packet was seen in 64bit floating point seconds
 * @author Daniel Lawson
 * @author Perry Lorier
 */
SIMPLE_FUNCTION
double trace_get_seconds(const struct libtrace_packet_t *packet);

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
SIMPLE_FUNCTION
int trace_get_capture_length(const struct libtrace_packet_t *packet);

/** Get the size of the packet as it was seen on the wire.
 * @param packet  	the packet opaque pointer
 * @returns the size of the packet as it was on the wire.
 * @author Perry Lorier
 * @author Daniel Lawson
 * @note Due to the trace being a header capture, or anonymisation this may
 * not be the same as the Capture Len.
 */ 
SIMPLE_FUNCTION
int trace_get_wire_length(const struct libtrace_packet_t *packet);

/** Get the length of the capture framing headers.
 * @param packet  	the packet opaque pointer
 * @returns the size of the packet as it was on the wire.
 * @author Perry Lorier
 * @author Daniel Lawson
 * @note this length corresponds to the difference between the size of a 
 * captured packet in memory, and the captured length of the packet
 */ 
SIMPLE_FUNCTION
int trace_get_framing_length(const struct libtrace_packet_t *packet);


/** Link layer types
 * This enumates the various different link types that libtrace understands
 */
typedef enum { 
       TRACE_TYPE_LEGACY, 	
       TRACE_TYPE_HDLC_POS, 
       TRACE_TYPE_ETH,			/**< 802.3 style Ethernet */
       TRACE_TYPE_ATM,
       TRACE_TYPE_80211,		/**< 802.11 frames */
       TRACE_TYPE_NONE,
       TRACE_TYPE_LINUX_SLL,		/**< Linux "null" framing */
       TRACE_TYPE_PFLOG,		/**< FreeBSD's PFlug */
       TRACE_TYPE_LEGACY_DEFAULT,
       TRACE_TYPE_LEGACY_POS,
       TRACE_TYPE_LEGACY_ATM,
       TRACE_TYPE_LEGACY_ETH
     } libtrace_linktype_t;

/** Get the type of the link layer
 * @param packet  	the packet opaque pointer
 * @returns libtrace_linktype_t
 * @author Perry Lorier
 * @author Daniel Lawson
 */
SIMPLE_FUNCTION
inline libtrace_linktype_t trace_get_link_type(const struct libtrace_packet_t *packet);

/** Get the destination MAC addres
 * @param packet  	the packet opaque pointer
 * @returns a pointer to the destination mac, (or NULL if there is no 
 * destination MAC)
 * @author Perry Lorier
 */
SIMPLE_FUNCTION
uint8_t *trace_get_destination_mac(const struct libtrace_packet_t *packet);

/** Get the source MAC addres
 * @param packet  	the packet opaque pointer
 * @returns a pointer to the source mac, (or NULL if there is no source MAC)
 * @author Perry Lorier
 */
SIMPLE_FUNCTION
uint8_t *trace_get_source_mac(const struct libtrace_packet_t *packet);

/** Truncate the packet at the suggested length
 * @param packet	the packet opaque pointer
 * @param size		the new length of the packet
 * @returns the new length of the packet, or the original length of the 
 * packet if unchanged
 * @author Daniel Lawson
 */
size_t trace_set_capture_length(struct libtrace_packet_t *packet, size_t size);

/** Set the direction flag, if it has one
 * @param packet  	the packet opaque pointer
 * @param direction	the new direction (0,1,2,3)
 * @returns a signed value containing the direction flag, or -1 if this is not supported
 * @author Daniel Lawson
 */
int8_t trace_set_direction(struct libtrace_packet_t *packet, int8_t direction);

/** Get the direction flag, if it has one
 * @param packet  	the packet opaque pointer
 * @returns a signed value containing the direction flag, or -1 if this is not supported
 * The direction is defined as 0 for packets originating locally (ie, outbound)
 * and 1 for packets originating remotely (ie, inbound).
 * Other values are possible, which might be overloaded to mean special things
 * for a special trace.
 * @author Daniel Lawson
 */
SIMPLE_FUNCTION
int8_t trace_get_direction(const struct libtrace_packet_t *packet);

/** Event types 
 * see \ref libtrace_eventobj_t and \ref trace_event
 */
typedef enum {
	TRACE_EVENT_IOWAIT,	/**< Need to block on fd */
	TRACE_EVENT_SLEEP,	/**< Sleep for some time */
	TRACE_EVENT_PACKET,	/**< packet has arrived */
	TRACE_EVENT_TERMINATE	/**< End of trace */
} libtrace_event_t;

/** structure returned by libtrace_event explaining what the current event is */
struct libtrace_eventobj_t {
	libtrace_event_t type; /**< event type (iowait,sleep,packet) */
	int fd;		       /**< if IOWAIT, the fd to sleep on */
	double seconds;	       /**< if SLEEP, the amount of time to sleep for */
	int size; 	       /**< if PACKET, the value returned from trace_read_packet */
};

/** process a libtrace event
 * @param trace the libtrace opaque pointer
 * @param packet the libtrace_packet opaque pointer
 * @returns libtrace_event struct containing the type, and potential
 * 	fd or seconds to sleep on
 *
 * Type can be:
 *  TRACE_EVENT_IOWAIT	Waiting on I/O on fd
 *  TRACE_EVENT_SLEEP	Next event in seconds
 *  TRACE_EVENT_PACKET	Packet arrived in buffer with size size
 *  TRACE_EVENT_TERMINATE Trace terminated (perhaps with an error condition)
 */
struct libtrace_eventobj_t trace_event(struct libtrace_t *trace,
		struct libtrace_packet_t *packet);

/** setup a BPF filter
 * @param filterstring a char * containing the bpf filter string
 * @returns opaque pointer pointer to a libtrace_filter_t object
 * @author Daniel Lawson
 * @note The filter is not actually compiled at this point, so no correctness
 * tests are performed here. trace_bpf_setfilter will always return ok, but
 * if the filter is poorly constructed an error will be generated when the 
 * filter is actually used
 */
SIMPLE_FUNCTION
struct libtrace_filter_t *trace_bpf_setfilter(const char *filterstring);

/** apply a BPF filter
 * @param filter 	the filter opaque pointer
 * @param packet	the packet opaque pointer
 * @returns 0 if the filter fails, 1 if it succeeds
 * @author Daniel Lawson
 * @note Due to the way BPF filters are built, the filter is not actually compiled
 * until the first time trace_bpf_filter is called. If your filter is incorrect, it will generate an error message and assert, exiting the program. This behaviour may change to more graceful handling of this error in the future.
 */
int trace_bpf_filter(struct libtrace_filter_t *filter,
		const struct libtrace_packet_t *packet);


/** Which port is the server port */
typedef enum {
	USE_DEST, 	/**< Destination port is the server port */
	USE_SOURCE	/**< Source port is the server port */
} serverport_t;

/** Get the source port
 * @param packet	the packet to read from
 * @returns a port in \em HOST byte order, or equivilent to ports for this
 * protocol, or 0 if this protocol has no ports.
 * @author Perry Lorier
 */
SIMPLE_FUNCTION
uint16_t trace_get_source_port(const struct libtrace_packet_t *packet);

/** Get the destination port
 * @param packet	the packet to read from
 * @returns a port in \em HOST byte order, or equivilent to ports for this
 * protocol, or 0 if this protocol has no ports.
 * @author Perry Lorier
 */
SIMPLE_FUNCTION
uint16_t trace_get_destination_port(const struct libtrace_packet_t *packet);

/** hint at the server port in specified protocol
 * @param protocol	the IP layer protocol, eg 6 (tcp), 17 (udp)
 * @param source	the source port from the packet
 * @param dest		the destination port from the packet
 * @returns one of USE_SOURCE or USE_DEST depending on which one you should use
 * @note ports must be in \em HOST byte order!
 * @author Daniel Lawson
 */
SIMPLE_FUNCTION
int8_t trace_get_server_port(uint8_t protocol, uint16_t source, uint16_t dest);

/** Takes a uri and splits it into a format and uridata component. 
 * Primarily for internal use but made available for external use.
 * @param uri		the uri to be parsed
 * @param format	destination location for the format component of the uri 
 * @returns 0 if an error occured, otherwise returns the uridata component
 * @author Shane Alcock
 */
const char *trace_parse_uri(const char *uri, char **format);
#ifdef __cplusplus
} // extern "C"
#endif // #ifdef __cplusplus
#endif // LIBTRACE_H_
