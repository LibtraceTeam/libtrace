/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007 The University of Waikato, Hamilton, New Zealand.
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
/** @file */

#ifndef LIBTRACE_INT_H
#define LIBTRACE_INT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "common.h"
#include "config.h"
#include "libtrace.h"

#ifdef _MSC_VER
// warning: deprecated function
#pragma warning(disable:4996)
// warning: benign redefinitions of types
#pragma warning(disable:4142)
#endif

#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#else
# include "lt_inttypes.h"
#endif

#ifdef HAVE_STDDEF_H
# include <stddef.h>
#else
#ifndef WIN32
# error "Can't find stddev.h -- do you define ptrdiff_t elsewhere?"
#endif
#endif


#include "rt_protocol.h"
	
/* Prefer net/bpf.h over pcap-bpf.h for format_bpf.c on MacOS */
#ifdef HAVE_NET_BPF_H
#    include <net/bpf.h>
#    define HAVE_BPF 1
#else
#ifdef HAVE_PCAP_BPF_H
#  include <pcap-bpf.h>
#  define HAVE_BPF 1
#endif
#endif

#ifdef HAVE_PCAP_H
#  include <pcap.h>
#  ifdef HAVE_PCAP_INT_H
#    include <pcap-int.h>
#  endif
#endif 

#ifdef HAVE_ZLIB_H
#  include <zlib.h>
#endif

#ifndef HAVE_STRNCASECMP
# ifndef HAVE__STRNICMP
int strncasecmp(const char *str1, const char *str2, size_t n);
# else
# define strncasecmp _strnicmp
# endif
#endif

#ifndef HAVE_SNPRINTF
# ifndef HAVE_SPRINTF_S
int snprintf(char *str, size_t size, const char *format, ...);
# else
# define snprintf sprintf_s
# endif 
#endif

#include "daglegacy.h"
	
#ifdef HAVE_DAG_API
#  include "dagnew.h"
#  include "dagapi.h"
#	if DAG_VERSION == 25
#		include <daginf.h>
#	endif
#else
#  include "dagformat.h"
#endif

#define RP_BUFSIZE 65536U

struct libtrace_event_status_t {
	libtrace_packet_t *packet;
	int psize;
	double tdelta;
	double trace_last_ts;
};

/** The information about traces that are open 
 * @internal
 */
struct libtrace_t {
	struct libtrace_format_t *format; /**< format driver pointer */
	void *format_data; /**<format data pointer */
	bool started;			/**< if this trace has started */
	libtrace_err_t err;		/**< error information */
	struct libtrace_event_status_t event;	/**< the next event */
	char *uridata;			/**< the uri of this trace */
	struct libtrace_filter_t *filter; /**< used by libtrace if the module
					    * doesn't support filters natively
					    */
	size_t snaplen;		/**< used by libtrace if the module
					  * doesn't support snapping natively
					  */
};

/** Information about output traces
 * @internal
 */
struct libtrace_out_t {
        struct libtrace_format_t *format;	/**< format driver */
	void *format_data; 		/**< format data */
	bool started;			/**< trace started */
	libtrace_err_t err;		/**< Associated error */
	char *uridata;			/**< URI associated with this trace */
};

void trace_set_err(libtrace_t *trace, int errcode,const char *msg,...) 
								PRINTF(3,4);
void trace_set_err_out(libtrace_out_t *trace, int errcode, const char *msg,...)
								PRINTF(3,4);

typedef struct libtrace_sll_header_t {
	uint16_t pkttype;          	/* packet type */
	uint16_t hatype;           	/* link-layer address type */
	uint16_t halen;            	/* link-layer address length */
	char addr[8];	 		/* link-layer address */
	uint16_t protocol;         	/* protocol */
} libtrace_sll_header_t;

#define TRACE_SLL_HOST		0
#define TRACE_SLL_BROADCAST 	1
#define TRACE_SLL_MULTICAST	2
#define TRACE_SLL_OTHERHOST	3
#define TRACE_SLL_OUTGOING	4

#ifndef PF_RULESET_NAME_SIZE
#define PF_RULESET_NAME_SIZE 16
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

typedef struct libtrace_pflog_header_t {
	uint8_t	   length;
	sa_family_t   af;
	uint8_t	   action;
	uint8_t	   reason;
	char 	   ifname[IFNAMSIZ];
	char 	   ruleset[PF_RULESET_NAME_SIZE];
	uint32_t   rulenr;
	uint32_t   subrulenr;
	uint8_t	   dir;
	uint8_t	   pad[3];
} libtrace_pflog_header_t;



/** Module definition structure */
/* all of these should return -1, or NULL on failure */
struct libtrace_format_t {
	/** the uri name of this module */
	const char *name;
	/** the version of this module */
	const char *version;
	/** the RT protocol type of this module */
	enum base_format_t type;
	/** stuff that deals with input @{ */
	/** initialise an trace (or NULL if input is not supported) */
	int (*init_input)(libtrace_t *libtrace);
	/** configure an trace (or NULL if input is not supported) */
	int (*config_input)(libtrace_t *libtrace,trace_option_t option,void *value);
	/** start/unpause an trace (or NULL if input not supported) */
	int (*start_input)(libtrace_t *libtrace);
	/** pause an trace (or NULL if input not supported) */
	int (*pause_input)(libtrace_t *libtrace);
	/** @} */
	/** stuff that deals with output @{ */
	/** initialise output traces (or NULL if output not supported) */
	int (*init_output)(libtrace_out_t *libtrace);
	/** configure output traces (or NULL if output not supported) */
	int (*config_output)(libtrace_out_t *libtrace, trace_option_output_t option, void *);
	/** start output traces (or NULL if output not supported) 
	 * There is no pause for output traces, as packets are not arriving
	 * asyncronously
	 */
	int (*start_output)(libtrace_out_t *libtrace);
	/** @} */
	/** finish an input trace, cleanup (or NULL if input not supported) 
	 * if the trace is not paused, libtrace will pause the trace before
	 * calling this function.
	 */
	int (*fin_input)(libtrace_t *libtrace);
	/** finish an output trace, cleanup (or NULL if output not supported) */
	int (*fin_output)(libtrace_out_t *libtrace);
	/** read a packet from a trace into the provided packet structure 
	 * @returns -1 on error, or get_framing_length()+get_capture_length() \
	 * on success.
	 * if this function is not supported, this field may be NULL.
	 */
	int (*read_packet)(libtrace_t *libtrace, libtrace_packet_t *packet);
	/** finalise a packet
	 * cleanup any resources used by a packet that can't be reused for
	 * the next packet.
	 */
	void (*fin_packet)(libtrace_packet_t *packet);
	/** write a packet to a trace from the provided packet 
	 * (or NULL if output not supported)
	 */
	int (*write_packet)(libtrace_out_t *libtrace, libtrace_packet_t *packet);
	/** return the libtrace link type for this packet 
	 * @return the libtrace link type, or -1 if this link type is unknown
	 */ 
	libtrace_linktype_t (*get_link_type)(const libtrace_packet_t *packet);
	/** return the direction of this packet 
	 * @note This callback may be NULL if not supported.
	 */ 
	libtrace_direction_t (*get_direction)(const libtrace_packet_t *packet);
	/** set the direction of this packet 
	 * @note This callback may be NULL if not supported.
	 */ 
	libtrace_direction_t (*set_direction)(libtrace_packet_t *packet, libtrace_direction_t direction);
	/** return the erf timestamp of the packet.
	 * @return the 64bit erf timestamp
	 * This field may be NULL in the structure, and libtrace will
	 * synthesise the result from get_timeval or get_seconds if they
	 * exist.  AT least one of get_erf_timestamp, get_timeval or
	 * get_seconds must be implemented.
	 */
	uint64_t (*get_erf_timestamp)(const libtrace_packet_t *packet);
	/** return the timeval of this packet.
	 * @return the timeval
	 * This field may be NULL in the structure, and libtrace will
	 * synthesise the result from get_erf_timestamp or get_seconds if they
	 * exist.  AT least one of get_erf_timestamp, get_timeval or
	 * get_seconds must be implemented.
	 */
	struct timeval (*get_timeval)(const libtrace_packet_t *packet);
	/** return the timestamp of this packet.
	 * @return the floating point seconds since 1970-01-01 00:00:00
	 * This field may be NULL in the structure, and libtrace will
	 * synthesise the result from get_timeval or get_erf_timestamp if they
	 * exist.  AT least one of get_erf_timestamp, get_timeval or
	 * get_seconds must be implemented.
	 */
	double (*get_seconds)(const libtrace_packet_t *packet);
	/** move the pointer within the trace.
	 * @return 0 on success, -1 on failure.
	 * The next packet returned by read_packet be the first
	 * packet in the trace to have a timestamp equal or greater than
	 * timestamp.
	 * @note this function may be NULL if the format does not support
	 * this feature.  If the format implements seek_timeval and/or 
	 * seek_seconds then libtrace will call those functions instead.
	 */
	int (*seek_erf)(libtrace_t *trace, uint64_t timestamp);
	/** move the pointer within the trace.
	 * @return 0 on success, -1 on failure.
	 * The next packet returned by read_packet be the first
	 * packet in the trace to have a timestamp equal or greater than
	 * timestamp.
	 * @note this function may be NULL if the format does not support
	 * this feature.  If the format implements seek_erf and/or 
	 * seek_seconds then libtrace will call those functions instead.
	 */
	int (*seek_timeval)(libtrace_t *trace, struct timeval tv);
	/** move the pointer within the trace.
	 * @return 0 on success, -1 on failure.
	 * The next packet returned by read_packet be the first
	 * packet in the trace to have a timestamp equal or greater than
	 * tv.
	 * @note this function may be NULL if the format does not support
	 * this feature.  If the format implements seek_erf and/or 
	 * seek_timeval then libtrace will call those functions instead.
	 */
	int (*seek_seconds)(libtrace_t *trace, double seconds);
	/** return the captured payload length 
	 * @return the amount of data captured in a trace.
	 * This is the number of bytes actually in the trace.  This does not
	 * include the trace framing length.  This is usually shorter or
	 * equal to the wire length.
	 */
	int (*get_capture_length)(const libtrace_packet_t *packet);
	/** return the original length of the packet on the wire.
	 * @return the length of the packet on the wire before truncation.
	 * This is the number of bytes actually in the trace.  This does not
	 * include the trace framing length.  This is usually shorter or
	 * equal to the wire length.
	 */
	int (*get_wire_length)(const libtrace_packet_t *packet);
	/** return the length of the trace framing header
	 * @return the length of the framing header
	 * The framing header is the extra metadata a trace stores about
	 * a packet.  This does not include the wire or capture length
	 * of the packet.  Usually get_framing_length()+get_capture_length()
	 * is the size returned by read_packet
	 */
	int (*get_framing_length)(const libtrace_packet_t *packet);
	/** truncate (snap) the packet 
	 * @returns the new size
	 * @note This callback may be NULL if not supported.
	 */
	size_t (*set_capture_length)(struct libtrace_packet_t *packet,size_t size);
	/** return the filedescriptor associated with this interface.
	 * @note This callback may be NULL if not supported.
	 * This function is only needed if you use trace_event_interface
	 * as the pointer for trace_event
	 */
	int (*get_fd)(const libtrace_t *trace);
	/** return the next event from this source 
	 * @note may be NULL if not supported.
	 */
	struct libtrace_eventobj_t (*trace_event)(libtrace_t *trace, libtrace_packet_t *packet);	
	/** return information about this trace format to standard out */
	void (*help)(void);
	/** next pointer, should be NULL */
	struct libtrace_format_t *next;
};

extern struct libtrace_format_t *form;

void register_format(struct libtrace_format_t *format);

libtrace_linktype_t pcap_linktype_to_libtrace(libtrace_dlt_t linktype);
libtrace_rt_types_t pcap_linktype_to_rt(libtrace_dlt_t linktype);
libtrace_dlt_t libtrace_to_pcap_linktype(libtrace_linktype_t type);
libtrace_dlt_t libtrace_to_pcap_dlt(libtrace_linktype_t type);
libtrace_dlt_t rt_to_pcap_linktype(libtrace_rt_types_t rt_type);
libtrace_linktype_t erf_type_to_libtrace(uint8_t erf);
uint8_t libtrace_to_erf_type(libtrace_linktype_t linktype);
libtrace_linktype_t arphrd_type_to_libtrace(unsigned int);
unsigned int libtrace_to_arphrd_type(libtrace_linktype_t);

void promote_packet(libtrace_packet_t *packet);
bool demote_packet(libtrace_packet_t *packet);

void *trace_get_payload_from_linux_sll(void *, uint16_t *, uint32_t *);
void *trace_get_payload_from_pos(void *, uint16_t *, uint32_t *);
DLLEXPORT void *trace_get_payload_from_atm(void *, uint8_t *, uint32_t *);

uint64_t byteswap64(uint64_t num);
uint32_t byteswap32(uint32_t num);
uint16_t byteswap16(uint16_t num);

/* Because some traces/protocols are defined as
 * being "big endian" or "little endian" we have
 * this series of macros.
 */
#if BYTE_ORDER == BIG_ENDIAN
#define bswap_host_to_be64(num) ((uint64_t)(num))
#define bswap_host_to_le64(num) byteswap64(num)
#define bswap_host_to_be32(num) ((uint32_t)(num))
#define bswap_host_to_le32(num) byteswap32(num)
#define bswap_host_to_be16(num) ((uint16_t)(num))
#define bswap_host_to_le16(num) byteswap16(num)

#define bswap_be_to_host64(num) ((uint64_t)(num))
#define bswap_le_to_host64(num) byteswap64(num)
#define bswap_be_to_host32(num) ((uint32_t)(num))
#define bswap_le_to_host32(num) byteswap32(num)
#define bswap_be_to_host16(num) ((uint16_t)(num))
#define bswap_le_to_host16(num) byteswap16(num)

/* We use ntoh*() here, because the compiler may
 * attempt to optimise it
 */
#elif BYTE_ORDER == LITTLE_ENDIAN
#define bswap_host_to_be64(num) (byteswap64(num))
#define bswap_host_to_le64(num) ((uint64_t)(num))
#define bswap_host_to_be32(num) (htonl(num))
#define bswap_host_to_le32(num) ((uint32_t)(num))
#define bswap_host_to_be16(num) (htons(num))
#define bswap_host_to_le16(num) ((uint16_t)(num))

#define bswap_be_to_host64(num) (byteswap64(num))
#define bswap_le_to_host64(num) ((uint64_t)(num))
#define bswap_be_to_host32(num) (ntohl(num))
#define bswap_le_to_host32(num) ((uint32_t)(num))
#define bswap_be_to_host16(num) (ntohs(num))
#define bswap_le_to_host16(num) ((uint16_t)(num))

#else
#error "Unknown byte order"
#endif

#ifdef HAVE_BPF
/* A type encapsulating a bpf filter
 * This type covers the compiled bpf filter, as well as the original filter
 * string
 *
 */
struct libtrace_filter_t {
	struct bpf_program filter;
	int flag;
	char * filterstring;
};
#else
struct libtrace_filter_t {};
#endif

/** libtrace packet 
 */
typedef struct libtrace_pcapfile_pkt_hdr_t {
	uint32_t ts_sec;
	uint32_t ts_usec;
	uint32_t caplen;
	uint32_t wirelen;
} libtrace_pcapfile_pkt_hdr_t;

#ifdef HAVE_DAG
void dag_constructor(void);
#endif
void erf_constructor(void);
void tsh_constructor(void);
void legacy_constructor(void);
void linuxnative_constructor(void);
void pcap_constructor(void);
void pcapfile_constructor(void);
void rt_constructor(void);
void duck_constructor(void);
void atmhdr_constructor(void);
#ifdef HAVE_BPF
void bpf_constructor(void);
#endif

/* Used internally by get_wire_length() methods */
bool trace_get_wireless_flags(void *link, libtrace_linktype_t linktype, uint8_t *flags);
#define TRACE_RADIOTAP_F_FCS 0x10
	
#ifdef __cplusplus
}
#endif

#endif /* LIBTRACE_INT_H */
