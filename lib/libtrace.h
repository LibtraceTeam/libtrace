#ifndef _LIBTRACE_H_
#define _LIBTRACE_H_
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
 * <li> include "libtrace.h" (found in /usr/local/wand/include
 * on voodoo and chasm).
 * <li> call create_trace with the uri of the trace you're interested in.<br>
 * This is usually passed in as argv[1] to your program.
 * <li> call libtrace_read_packet(), passing in the libtrace_t returned from
 * create trace and a buffer (and the buffer length)
 * <li> call getIP() on the buffer, and do whatever you need
 * <li> loop back to step 3, until libtrace_read_packet() returns -1
 * </ol>
 * @par Linking
 * To use this library you need to link against -ltrace, -lpcapl and -lzl
 * which are the versions of these libraries that support >2G files.  (grr!)
 * These can be found in /usr/local/wand/lib on voodoo and chasm.
 *
 *
 */

#define COLLECTOR_PORT 3435

/** Opaque structure holding information about a trace */
struct libtrace_t;
        
/** Opaque structure holding information about a bpf filter */

struct libtrace_filter_t;
/** Structure for dealing with IP packets */
struct libtrace_ip
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;		/**< header length */
    unsigned int ip_v:4;		/**< version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;		/**< version */
    unsigned int ip_hl:4;		/**< header length */
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
    struct in_addr ip_src, ip_dst;	/**< source and dest address */
  };

/** Structure for dealing with TCP packets */
struct libtrace_tcp
  {
    u_int16_t source;		/**< Source Port */
    u_int16_t dest;		/**< Destination port */
    u_int32_t seq;		/**< Sequence number */
    u_int32_t ack_seq;		/**< Acknowledgement Number */
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;		/**< Reserved bits */
    u_int16_t doff:4;		
    u_int16_t fin:1;		/**< FIN */
    u_int16_t syn:1;		/**< SYN flag */
    u_int16_t rst:1;		/**< RST flag */
    u_int16_t psh:1;		/**< PuSH flag */
    u_int16_t ack:1;		/**< ACK flag */
    u_int16_t urg:1;		/**< URG flag */
    u_int16_t res2:2;		/**< Reserved */
#  elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;		
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
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
  u_int8_t type;		/* message type */
  u_int8_t code;		/* type sub-code */
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t	id;
      u_int16_t	sequence;
    } echo;			/* echo datagram */
    u_int32_t	gateway;	/* gateway address */
    struct
    {
      u_int16_t	__unused;
      u_int16_t	mtu;
    } frag;			/* path mtu discovery */
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
struct libtrace_t *create_trace(char *uri);

/** Close a trace file, freeing up any resources it may have been using
 *
 */
void destroy_trace(struct libtrace_t *rtclient);

/** Read one packet from the trace into buffer
 *
 * @param libtrace      the trace to read from
 * @param buffer        the buffer to read into
 * @param len           the length of the buffer
 * @param status	status of the trace (only used for RTClients)
 * @returns number of bytes copied, -1 on error, or 0 at EOF
 *
 * @note the buffer must be at least as large as the largest packet (plus
 * link layer, and trace packet metadata overhead)
 */
int libtrace_read_packet(struct libtrace_t *rtclient, void *buffer, size_t len, int *status);

/** get a pointer to the link layer
 * @param libtrace      a pointer to the trace object returned from gettrace
 * @param buffer        a pointer to a filled in buffer
 * @param buflen        a pointer to the size of the buffer
 *
 * @returns a pointer to the link layer, or NULL if there is no link layer
 *
 * @note you should call getLinkType() to find out what type of link layer 
 * this is
 */
void *get_link(struct libtrace_t *libtrace, void *buffer, int buflen);

/** get a pointer to the IP header (if any)
 * @param libtrace      a pointer to the trace object returned from gettrace
 * @param buffer        a pointer to a filled in buffer
 * @param buflen        a pointer to the size of the buffer
 *
 * @returns a pointer to the IP header, or NULL if there is not an IP packet
 */
struct libtrace_ip *get_ip(struct libtrace_t *libtrace, void *buffer, int buflen);

/** get a pointer to the TCP header (if any)
 * @param libtrace      a pointer to the trace object returned from gettrace
 * @param buffer        a pointer to a filled in buffer
 * @param buflen        a pointer to the size of the buffer
 *
 * @returns a pointer to the TCP header, or NULL if there is not a TCP packet
 */
struct libtrace_tcp *get_tcp(struct libtrace_t *libtrace, void *buffer, int buflen);

/** get a pointer to the UDP header (if any)
 * @param libtrace      a pointer to the trace object returned from gettrace
 * @param buffer        a pointer to a filled in buffer
 * @param buflen        a pointer to the size of the buffer
 *
 * @returns a pointer to the UDP header, or NULL if this is not a UDP packet
 */
struct libtrace_udp *get_udp(struct libtrace_t *libtrace, void *buffer, int buflen);

/** get a pointer to the ICMP header (if any)
 * @param libtrace      a pointer to the trace object returned from gettrace
 * @param buffer        a pointer to a filled in buffer
 * @param buflen        a pointer to the size of the buffer
 *
 * @returns a pointer to the ICMP header, or NULL if this is not a ICMP packet
 */
struct libtrace_icmp *get_icmp(struct libtrace_t *libtrace, void *buffer, int buflen);

/** Get the current time in DAG time format 
 * @param libtrace the libtrace opaque pointer
 * @param buffer a pointer to a filled in buffer
 * @param buflen the length of the buffer
 * @returns a 64 bit timestamp in DAG ERF format (upper 32 bits are the seconds
 * past 1970-01-01, the lower 32bits are partial seconds)
 * @author Daniel Lawson
 */
uint64_t get_erf_timestamp(struct libtrace_t *libtrace, void *buffer, int buflen);

/** Get the current time in struct timeval
 * @param libtrace the libtrace opaque pointer
 * @param buffer a pointer to a filled in buffer
 * @param buflen the length of the buffer
 * @returns time that this packet was seen in a struct timeval
 * @author Daniel Lawson
 * @author Perry Lorier
 */ 

struct timeval get_timeval(struct libtrace_t *libtrace, void *buffer, int buflen);

/** Get the current time in floating point seconds
 * @param libtrace the libtrace opaque pointer
 * @param buffer a pointer to a filled in buffer
 * @param buflen the length of the buffer
 * @returns time that this packet was seen in 64bit floating point seconds
 * @author Perry Lorier
 */
double get_seconds(struct libtrace_t *libtrace, void *buffer, int buflen);

/** Get the size of the packet in the trace
 * @param libtrace the libtrace opaque pointer
 * @param buffer a pointer to a filled in buffer
 * @param buflen the length of the buffer
 * @returns the size of the packet in the trace
 * @author Perry Lorier
 * @note Due to this being a header capture, or anonymisation, this may not
 * be the same size as the original packet.  See get_wire_length() for the original
 * size of the packet.
 * @note This can (and often is) different for different packets in a trace!
 * @par 
 *  This is sometimes called the "snaplen".
 */

int get_capture_length(struct libtrace_t *libtrace, void *buffer, int buflen);

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

int get_wire_length(struct libtrace_t *libtrace, void *buffer, int buflen);

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
 * @param libtrace the libtrace opaque pointer
 * @param buffer a pointer to a filled in buffer
 * @param buflen the length of the buffer
 * @returns libtrace_linktype_t
 * @author Perry Lorier
 * @author Daniel Lawson
 */

inline libtrace_linktype_t get_link_type(
		struct libtrace_t *libtrace,
		void *buffer,
		int buflen);	

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
			int buflen);

/** Get the source MAC addres
 * @param libtrace the libtrace opaque pointer
 * @param buffer a pointer to a filled in buffer
 * @param buflen the length of the buffer
 * @returns a pointer to the source mac, (or NULL if there is no source MAC)
 * @author Perry Lorier
 */
uint8_t *get_source_mac(struct libtrace_t *libtrace,
			void *buffer,
			int buflen);

/** Event types */
typedef enum {
	TRACE_EVENT_IOWAIT,
	TRACE_EVENT_SLEEP,
	TRACE_EVENT_PACKET
} libtrace_event_t;

/** process a libtrace event
 * @returns
 *  TRACE_EVENT_IOWAIT	Waiting on I/O on <fd>
 *  TRACE_EVENT_SLEEP	Next event in <seconds>
 *  TRACE_EVENT_PACKET	Packet arrived in <buffer> with size <size>
 */
libtrace_event_t libtrace_event(struct libtrace_t *trace,
			int *fd,double *seconds,
			void *buffer, int *size);

/** setup a BPF filter
 * @param filterstring a char * containing the bpf filter string
 * @returns opaque pointer pointer to a libtrace_filter_t object
 * @author Daniel Lawson
 */
struct libtrace_filter_t *libtrace_bpf_setfilter(const char *filterstring);

/** apply a BPF filter
 * @param libtrace the libtrace opaque pointer
 * @param filter the filter opaque pointer
 * @param buffer a pointer to a filled buffer
 * @param buflen the length of the buffer
 * @returns the return value from bpf_filter
 * @author Daniel Lawson
 */
int libtrace_bpf_filter(struct libtrace_t *trace,
			struct libtrace_filter_t *filter,
			void *buffer, 
			int buflen);


#endif // _LIBTRACE_H_
