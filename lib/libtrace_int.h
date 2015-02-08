/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Daniel Lawson 
 *          Perry Lorier
 *          Shane Alcock 
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
 * @brief Header file containing definitions for structures and functions that
 * are internal
 *
 * @author Daniel Lawson
 * @author Perry Lorier
 * @author Shane Alcock
 *
 * @version $Id$
 *
 * All of the structures and functions defined in this header file are intended
 * for internal use within Libtrace only. They should not be exported as part
 * of the library API as we don't want users accessing things like the
 * contents of the libtrace packet structure directly!
 */
#ifndef LIBTRACE_INT_H
#define LIBTRACE_INT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#include "common.h"
#include "libtrace.h"
#include "wandio.h"
#include "lt_bswap.h"

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

#ifndef HAVE_STRNDUP
char *strndup(const char *s, size_t size);
#endif

#ifndef HAVE_STRNCASECMP
# ifndef HAVE__STRNICMP
/** A local implementation of strncasecmp (as some systems do not have it) */
int strncasecmp(const char *str1, const char *str2, size_t n);
# else
# define strncasecmp _strnicmp
# endif
#endif

#ifndef HAVE_SNPRINTF
# ifndef HAVE_SPRINTF_S
/** A local implementation of snprintf (as some systems do not have it) */
int snprintf(char *str, size_t size, const char *format, ...);
# else
# define snprintf sprintf_s
# endif 
#endif

#include "daglegacy.h"
	
#ifdef HAVE_DAG_API
#  include "dagnew.h"
#  include "dagapi.h"
#	if DAG_VERSION == 24
#		include <erftypes.h>
#	else
#		include <daginf.h>
#	endif
#  include "erftypes.h"
#else
#  include "dagformat.h"
#endif

#ifdef HAVE_LLVM
#include "bpf-jit/bpf-jit.h"
#endif


//#define RP_BUFSIZE 65536U

/** Data about the most recent event from a trace file */
struct libtrace_event_status_t {
	/** A libtrace packet to store the packet when a PACKET event occurs */
	libtrace_packet_t *packet;
	/** Time between the timestamp for the current packet and the current 
	 * walltime */
	double tdelta;
	/** The timestamp of the previous PACKET event */
	double trace_last_ts;
	/** The size of the current PACKET event */
	int psize;
	/** Whether there is a packet stored in *packet above waiting for an
	 * event to occur */
	bool waiting;
};

/** A libtrace input trace 
 * @internal
 */
struct libtrace_t {
	/** The capture format for the input trace */
	struct libtrace_format_t *format; 
	/** Details of the most recent PACKET event reported by the trace */
	struct libtrace_event_status_t event;
	/** Pointer to the "global" data for the capture format module */	
	void *format_data; 		
	/** A BPF filter to be applied to all packets read by the trace - 
	 * used only if the capture format does not support filters natively */
	struct libtrace_filter_t *filter; 
	/** The snap length to be applied to all packets read by the trace - 
	 * used only if the capture format does not support snapping natively */
	size_t snaplen;			
	/** Count of the number of packets returned to the libtrace user */
	uint64_t accepted_packets;	
	/** Count of the number of packets filtered by libtrace */
	uint64_t filtered_packets;	
	/** The filename from the uri for the trace */
	char *uridata;			
	/** The libtrace IO reader for this trace (if applicable) */
	io_t *io;			
	/** Error information for the trace */
	libtrace_err_t err;		
	/** Boolean flag indicating whether the trace has been started */
	bool started;			
};

/** A libtrace output trace
 * @internal
 */
struct libtrace_out_t {
	/** The capture format for the output trace */
        struct libtrace_format_t *format;
	/** Pointer to the "global" data for the capture format module */
	void *format_data; 		
	/** The filename for the uri for the output trace */
	char *uridata;			
	/** Error information for the output trace */
	libtrace_err_t err;
	/** Boolean flag indicating whether the trace has been started */
	bool started;			
};

/** Sets the error status on an input trace
 *
 * @param trace		The input trace to set the error status for
 * @param errcode	The code for the error - can be a libtrace error code or a regular errno value
 * @param msg 		A message to print when reporting the error
 */
void trace_set_err(libtrace_t *trace, int errcode,const char *msg,...) 

								PRINTF(3,4);
/** Sets the error status on an output trace
 *
 * @param trace		The output trace to set the error status for
 * @param errcode	The code for the error - can be a libtrace error code or a regular errno value
 * @param msg 		A message to print when reporting the error
 */
void trace_set_err_out(libtrace_out_t *trace, int errcode, const char *msg,...)
								PRINTF(3,4);

/** Clears the cached values for a libtrace packet
 *
 * @param packet	The libtrace packet that requires a cache reset
 */
void trace_clear_cache(libtrace_packet_t *packet);

/** Converts the data provided in buffer into a valid libtrace packet
 *
 * @param trace		An input trace of the same format as the "packet" 
 * 			contained in the buffer
 * @param packet	The libtrace packet to prepare
 * @param buffer	A buffer containing the packet data, including the
 * 			capture format header
 * @param rt_type	The RT type for the packet that is being prepared
 * @param flags		Used to specify options for the preparation function,
 * 			e.g. who owns the packet buffer
 *
 * @return -1 if an error occurs, 0 otherwise 
 *
 * Packet preparation is a tricky concept - the idea is to take the data
 * pointed to by 'buffer' and treat it as a packet record of the same capture
 * format as that used by the input trace. The provided libtrace packet then
 * has its internal pointers and values set to describe the packet record in
 * the buffer. 
 *
 * The primary use of this function is to allow the RT packet reader to 
 * easily and safely convert packets from the RT format back into the format
 * that they were originally captured with., essentially removing the RT
 * encapsulation.
 *
 * We've decided not to make this function available via the exported API 
 * because there are several issues that can arise if it is not used very
 * carefully and it is not very useful outside of internal contexts anyway.
 */
int trace_prepare_packet(libtrace_t *trace, libtrace_packet_t *packet,
		void *buffer, libtrace_rt_types_t rt_type, uint32_t flags);

/** Flags for prepare_packet functions */
enum {
	/** The buffer memory has been allocated by libtrace and should be
	 * freed when the packet is destroyed. */
	TRACE_PREP_OWN_BUFFER		=1,
	
	/** The buffer memory is externally-owned and must not be freed by 
	 * libtrace when the packet is destroyed. */
	TRACE_PREP_DO_NOT_OWN_BUFFER	=0
};


#ifndef PF_RULESET_NAME_SIZE
#define PF_RULESET_NAME_SIZE 16
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif


/** A local definition of a PFLOG header */
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
} PACKED libtrace_pflog_header_t;



/** A libtrace capture format module */
/* All functions should return -1, or NULL on failure */
struct libtrace_format_t {
	/** The name of this module, used in the libtrace URI to identify the
	 * capture format */
	const char *name;
	/** The version of this module */
	const char *version;
	/** The RT protocol type of this module */
	enum base_format_t type;


	/** Given a filename, return if this is the most likely capture format
 	 * (used for devices). Used to "guess" the capture format when the
	 * URI is not fully specified.
	 *
	 * @param fname 	The name of the device or file to examine
	 * @return 1 if the name matches the capture format, 0 otherwise
 	 */
	int (*probe_filename)(const char *fname);
	
	/** Given a file, looks at the start of the file to determine if this
	 * is the capture format. Used to "guess" the capture format when the
	 * URI is not fully specified.
	 *
	 * @param io		An open libtrace IO reader for the file to check
	 * @return 1 if the file matches the capture format, 0 otherwise
	 */
	int (*probe_magic)(io_t *io);

	/** Initialises an input trace using the capture format.
	 *
	 * @param libtrace 	The input trace to be initialised
	 * @return 0 if successful, -1 in the event of error 
	 */
	int (*init_input)(libtrace_t *libtrace);
	
	/** Applies a configuration option to an input trace.
	 *
	 * @param libtrace	The input trace to apply the option to
	 * @param option	The option that is being configured
	 * @param value		A pointer to the value that the option is to be
	 * 			set to
	 * @return 0 if successful, -1 if the option is unsupported or an error
	 * occurs
	 */
	int (*config_input)(libtrace_t *libtrace,trace_option_t option,void *value);
	/** Starts or unpauses an input trace - note that this function is
	 * often the one that opens the file or device for reading.
	 *
	 * @param libtrace	The input trace to be started or unpaused
	 * @return 0 if successful, -1 in the event of error */
	int (*start_input)(libtrace_t *libtrace);

	/** Pauses an input trace - this function should close or detach the
	 * file or device that is being read from. 
	 *
	 * @param libtrace	The input trace to be paused
	 * @return 0 if successful, -1 in the event of error
	 */
	int (*pause_input)(libtrace_t *libtrace);

	/** Initialises an output trace using the capture format.
	 *
	 * @param libtrace	The output trace to be initialised
	 * @return 0 if successful, -1 in the event of error
	 */
	int (*init_output)(libtrace_out_t *libtrace);
	
	/** Applies a configuration option to an output trace.
	 *
	 * @param libtrace      The output trace to apply the option to 
	 * @param option        The option that is being configured
	 * @param value         A pointer to the value that the option is to be
	 * 			set to
	 * @return 0 if successful, -1 if the option is unsupported or an error
	 * occurs
	 * */
	int (*config_output)(libtrace_out_t *libtrace, trace_option_output_t option, void *value);

	/** Starts an output trace - note that this function is often the one
	 * that opens the file or device for writing.
	 *
	 * @param libtrace 	The output trace to be started
	 * @return 0 if successful, -1 if an error occurs
	 *
	 * There is no pause for output traces, as writing is not performed
	 * asynchronously.
	 */
	int (*start_output)(libtrace_out_t *libtrace);

	/** Concludes an input trace and cleans up the capture format data.
	 *
	 * @param libtrace 	The input trace to be concluded
	 * @return 0 if successful, -1 if an error occurs
	 *
	 * Libtrace will call the pause_input function if the input trace is
	 * currently active prior to calling this function.
	 */
	int (*fin_input)(libtrace_t *libtrace);

	/** Concludes an output trace and cleans up the capture format data.
	 *
	 * @param libtrace 	The output trace to be concluded
	 * @return 0 if successful, -1 if an error occurs
	 */
	int (*fin_output)(libtrace_out_t *libtrace);

	/** Reads the next packet from an input trace into the provided packet 
	 * structure.
	 *
	 * @param libtrace	The input trace to read from
	 * @param packet	The libtrace packet to read into
	 * @return The size of the packet read (in bytes) including the capture
	 * framing header, or -1 if an error occurs. 0 is returned in the
	 * event of an EOF. 
	 *
	 * If no packets are available for reading, this function should block
	 * until one appears or return 0 if the end of a trace file has been
	 * reached.
	 */
	int (*read_packet)(libtrace_t *libtrace, libtrace_packet_t *packet);
	
	/** Converts a buffer containing a packet record into a libtrace packet
	 * 
	 * @param libtrace	An input trace in the capture format for the 
	 * 			packet
	 * @param packet	A libtrace packet to put the prepared packet
	 * 			into
	 * @param buffer	The buffer containing the packet record 
	 * 			(including the capture format header)
	 * @param rt_type	The RT type for the packet
	 * @param flags		Flags describing properties that should be
	 * 			applied to the new packet
	 * @return 0 if successful, -1 if an error occurs.
	 *
	 * Updates internal trace and packet details, such as payload pointers,
	 * loss counters and packet types to match the packet record provided
	 * in the buffer. This is a zero-copy function.
	 *
	 * Intended (at this stage) only for internal use, particularly by
	 * RT which needs to decapsulate RT packets */
	int (*prepare_packet)(libtrace_t *libtrace, libtrace_packet_t *packet,
			void *buffer, libtrace_rt_types_t rt_type, 
			uint32_t flags);
	
	/** Frees any resources allocated by the capture format module for a
	 * libtrace packet.
	 *
	 * @param The packet to be finalised
	 * 	 */
	void (*fin_packet)(libtrace_packet_t *packet);

	/** Write a libtrace packet to an output trace.
	 *
	 * @param libtrace 	The output trace to write the packet to
	 * @param packet	The packet to be written out
	 * @return The number of bytes written, or -1 if an error occurs
	 */
	int (*write_packet)(libtrace_out_t *libtrace, libtrace_packet_t *packet);
	/** Returns the libtrace link type for a packet.
	 *
	 * @param packet 	The packet to get the link type for
	 * @return The libtrace link type, or -1 if this link type is unknown
	 */ 
	libtrace_linktype_t (*get_link_type)(const libtrace_packet_t *packet);

	/** Returns the direction of a packet.
	 *
	 * @param packet 	The packet to get the direction for
	 * @return The direction of the packet, or -1 if no direction tag is
	 * present or an error occurs
	 */ 
	libtrace_direction_t (*get_direction)(const libtrace_packet_t *packet);
	
	/** Sets the direction of a packet.
	 *
	 * @param packet	The packet to set the direction for
	 * @param direction	The direction to assign to the packet
	 * @return The updated direction for the packet, or -1 if an error
	 * occurs
	 *
	 * @note Some capture formats do not feature direction tagging, so it
	 * will not make sense to implement a set_direction function for them.
	 */ 
	libtrace_direction_t (*set_direction)(libtrace_packet_t *packet, libtrace_direction_t direction);
	
	/** Returns the timestamp for a packet in the ERF timestamp format.
	 *
	 * @param packet	The packet to get the timestamp from
	 * @return The 64-bit ERF timestamp
	 *
	 * @note Each format must implement at least one of the four "get 
	 * timestamp" functions. 
	 *
	 * If not implemented, libtrace will convert the result of one of the
	 * other timestamp functions into the appropriate format instead. 
	 * This means each capture format only needs to implement the most
	 * sensible of the four and let libtrace handle any conversions.
	 *
	 */
	uint64_t (*get_erf_timestamp)(const libtrace_packet_t *packet);

	/** Returns the timestamp for a packet in the timeval format
	 *
	 * @param packet	The packet to get the timestamp from
	 * @return The timestamp from the packet as a timeval
	 *
	 * @note Each format must implement at least one of the four "get 
	 * timestamp" functions. 
	 *
	 * If not implemented, libtrace will convert the result of one of the
	 * other timestamp functions into the appropriate format instead. 
	 * This means each capture format only needs to implement the most
	 * sensible of the four and let libtrace handle any conversions.
	 */
	struct timeval (*get_timeval)(const libtrace_packet_t *packet);
	
	/** Returns the timestamp for a packet in the timespec format.
	 *
	 * @param packet	The packet to get the timestamp from
	 * @return The timestamp from the packet as a timespec
	 *
	 * @note Each format must implement at least one of the four "get 
	 * timestamp" functions. 
	 *
	 * If not implemented, libtrace will convert the result of one of the
	 * other timestamp functions into the appropriate format instead. 
	 * This means each capture format only needs to implement the most
	 * sensible of the four and let libtrace handle any conversions.
	 */
	struct timespec (*get_timespec)(const libtrace_packet_t *packet);
	
	/** Returns the timestamp for a packet in floating point seconds.
	 *
	 * @param packet	The packet to get the timestamp from
	 * @return The timestamp from the packet as a floating point number of
	 * seconds since 1970-01-01 00:00:00 UTC
	 *
	 * @note Each format must implement at least one of the four "get 
	 * timestamp" functions. 
	 *
	 * If not implemented, libtrace will convert the result of one of the
	 * other timestamp functions into the appropriate format instead. 
	 * This means each capture format only needs to implement the most
	 * sensible of the four and let libtrace handle any conversions.
	 */
	double (*get_seconds)(const libtrace_packet_t *packet);
	
	/** Moves the read pointer to a certain ERF timestamp within an input 
	 * trace file.
	 *
	 * @param trace		The input trace to seek within
	 * @param timestamp	The timestamp to seek to, as an ERF timestamp
	 *
	 * @return 0 on success, -1 on failure.
	 *
	 * The next packet read from this trace will now be the first packet
	 * to have a timestamp equal to or greater than the provided timestamp.
	 *
	 * @note Each format that supports seeking must implement at least one
	 * of the seek functions.
	 *
	 * If not implemented, libtrace will convert the timestamp into the
	 * appropriate format to use a seek function that has been implemented.
	 * This means each capture format only needs to implement the seek
	 * function that matches the native timestamp format for that capture.
	 *
	 */
	int (*seek_erf)(libtrace_t *trace, uint64_t timestamp);
	/** Moves the read pointer to a certain timestamp represented using a
	 * timeval within an input trace file.
	 *
	 * @param trace		The input trace to seek within
	 * @param timestamp	The timestamp to seek to, as a timeval
	 *
	 * @return 0 on success, -1 on failure.
	 *
	 * The next packet read from this trace will now be the first packet
	 * to have a timestamp equal to or greater than the provided timestamp.
	 *
	 * @note Each format that supports seeking must implement at least one
	 * of the seek functions.
	 *
	 * If not implemented, libtrace will convert the timestamp into the
	 * appropriate format to use a seek function that has been implemented.
	 * This means each capture format only needs to implement the seek
	 * function that matches the native timestamp format for that capture.
	 *
	 */
	int (*seek_timeval)(libtrace_t *trace, struct timeval tv);
	
	/** Moves the read pointer to a certain timestamp represented using 
	 * floating point seconds within an input trace file.
	 *
	 * @param trace		The input trace to seek within
	 * @param timestamp	The timestamp to seek to, as floating point
	 * 			seconds since 1970-01-01 00:00:00 UTC
	 *
	 * @return 0 on success, -1 on failure.
	 *
	 * The next packet read from this trace will now be the first packet
	 * to have a timestamp equal to or greater than the provided timestamp.
	 *
	 * @note Each format that supports seeking must implement at least one
	 * of the seek functions.
	 *
	 * If not implemented, libtrace will convert the timestamp into the
	 * appropriate format to use a seek function that has been implemented.
	 * This means each capture format only needs to implement the seek
	 * function that matches the native timestamp format for that capture.
	 *
	 */
	int (*seek_seconds)(libtrace_t *trace, double seconds);
	
	/** Returns the payload length of the captured packet record.
	 *
	 * @param packet	The packet to get the capture length from
	 * @return The capture length for the packet, or -1 if an error occurs
	 *
	 * Capture length is the current size of the packet record itself,
	 * following any truncation that may have occurred during the capture
	 * process. This length does not include the capture format framing
	 * header.
	 */
	int (*get_capture_length)(const libtrace_packet_t *packet);

	/** Returns the original length of the packet as it was on the wire.
	 *
	 * @param packet	The packet to get the wire length from
	 * @return The length of the packet on the wire at the time of capture,
	 * or -1 if an error occurs
	 *
	 * Wire length is the original size of the packet prior to any
	 * truncation that may have occurred as part of the capture process.
	 * This length does not include the capture format framing header.
	 */
	int (*get_wire_length)(const libtrace_packet_t *packet);
	
	/** Returns the length of the capture format framing header
	 *
	 * @param packet	The packet to get the framing length from
	 * @return The length of the framing header, or -1 if an error occurs
	 *
	 * The framing header is the extra metadata that the capture process
	 * records about a packet.  The framing length does not include any
	 * of the packet payload itself. The total size of the packet record
	 * can be calculated be adding this value with the capture length.
	 */
	int (*get_framing_length)(const libtrace_packet_t *packet);

	/** Sets the capture length for a packet.
	 *
	 * @param packet 	The packet to adjust the capture length for.
	 * @param size		The new capture length
	 * @return The new capture length of the packet, or -1 if an error
	 * occurs
	 *
	 * @note This function should only reduce the capture length. If the
	 * provided length is larger than the current capture length, -1 should
	 * be returned.
	 */
	size_t (*set_capture_length)(struct libtrace_packet_t *packet,size_t size);
	/** Returns the number of packets observed by an input trace.
	 *
	 * @param trace		The input trace to get the packet count for
	 * @return The number of packets observed by an input trace, or
	 * UINT64_MAX if the number is unknown
	 *
	 * This count includes packets that have been filtered and dropped.
	 */
	uint64_t (*get_received_packets)(libtrace_t *trace);

	/** Returns the number of packets filtered by an input trace.
	 *
	 * @param trace		The input trace to get the filtered count for
	 * @return The number of packets filtered by the input trace, or
	 * UINT64_MAX if the number is unknown
	 *
	 */
	uint64_t (*get_filtered_packets)(libtrace_t *trace);
	
	/** Returns the number of packets dropped by an input trace.
	 *
	 * @param trace		The input trace to get the dropped count for
	 * @return The number of packets dropped by the input trace, or
	 * UINT64_MAX if the number is unknown
	 *
	 */
	uint64_t (*get_dropped_packets)(libtrace_t *trace);
	
	/** Returns the number of packets captured and returned by an input 
	 * trace.
	 *
	 * @param trace		The input trace to get the capture count for
	 * @return The number of packets returned to the libtrace user, or
	 * UINT64_MAX if the number is unknown
	 *
	 * This is the number of packets that have been successfully returned
	 * to the libtrace user via the read_packet() function.
	 *
	 */
	uint64_t (*get_captured_packets)(libtrace_t *trace);
	
	/** Returns the file descriptor used by the input trace.
	 *
	 * @param trace		The input trace to get the file descriptor for
	 * @return The file descriptor used by the input trace to read packets 
	 *
	 */
	int (*get_fd)(const libtrace_t *trace);
	
	/** Returns the next libtrace event for the input trace.
	 *
	 * @param trace		The input trace to get the next event from
	 * @param packet	A libtrace packet to read a packet into
	 * @return A libtrace event describing the event that occured
	 *
	 * The event API allows for non-blocking reading of packets from an
	 * input trace. If a packet is available and ready to be read, a packet
	 * event should be returned. Otherwise a sleep or fd event should be
	 * returned to indicate that the caller needs to wait. If the input
	 * trace has an error or reaches EOF, a terminate event should be
	 * returned.
	 */
	struct libtrace_eventobj_t (*trace_event)(libtrace_t *trace, libtrace_packet_t *packet);	

	/** Prints some useful help information to standard output. */
	void (*help)(void);

	/** Next pointer, should always be NULL - used by the format module
	 * manager. */
	struct libtrace_format_t *next;
};

/** The list of registered capture formats */
//extern struct libtrace_format_t *form;

/** Specifies whether any blocking packet readers should cease reading 
 * immediately
 */
extern volatile int libtrace_halt;

/** Registers a new capture format module.
 *
 * @param format	The format module to be registered
 */
void register_format(struct libtrace_format_t *format);

/** Converts a PCAP DLT into a libtrace link type.
 *
 * @param linktype	The PCAP DLT to be converted
 * @return The libtrace link type that is equivalent to the provided DLT, or 
 * -1 if the DLT is unknown
 */
libtrace_linktype_t pcap_linktype_to_libtrace(libtrace_dlt_t linktype);

/** Converts a PCAP DLT into an RT protocol type.
 *
 * @param linktype	The PCAP DLT to be converted
 * @return The RT type that is equivalent to the provided DLT
 */
libtrace_rt_types_t pcap_linktype_to_rt(libtrace_dlt_t linktype);

/** Converts a libtrace link type into a PCAP linktype.
 *
 * @param type		The libtrace link type to be converted
 * @return The PCAP linktype that is equivalent to the provided libtrace link 
 * type, or -1 if the link type is unknown
 */
libtrace_dlt_t libtrace_to_pcap_linktype(libtrace_linktype_t type);

/** Converts a libtrace link type into a PCAP DLT.
 *
 * @param type		The libtrace link type to be converted
 * @return The PCAP DLT that is equivalent to the provided libtrace link
 * type, or -1 if the link type is unknown
 */
libtrace_dlt_t libtrace_to_pcap_dlt(libtrace_linktype_t type);

/** Converts an RT protocol type into a PCAP DLT.
 *
 * @param rt_type	The RT type to be converted
 * @return The PCAP DLT that is equivalent to the provided RT protocol
 */
libtrace_dlt_t rt_to_pcap_linktype(libtrace_rt_types_t rt_type);

/** Converts a PCAP DLT into an RT protocol type for the BPF format.
 *
 * @param linktype	The PCAP DLT to be converted
 * @return The RT type that is equivalent to the provided DLT for BPF
 */
libtrace_rt_types_t bpf_linktype_to_rt(libtrace_dlt_t linktype);

/** Converts an ERF type into a libtrace link type.
 *
 * @param erf		The ERF type to be converted
 * @return The libtrace link type that is equivalent to the provided ERF type,
 * or -1 if the ERF type is unknown
 */
libtrace_linktype_t erf_type_to_libtrace(uint8_t erf);

/** Converts a libtrace link type into an ERF type.
 *
 * @param linktype	The libtrace link type to be converted
 * @return The ERF type that is equivalent to the provided libtrace link type,
 * or -1 if the link type cannot be matched to an ERF type.
 */
uint8_t libtrace_to_erf_type(libtrace_linktype_t linktype);

/** Converts an ARPHRD type into a libtrace link type.
 *
 * @param arphrd	The ARPHRD type to be converted
 * @return The libtrace link type that is equivalent to the provided ARPHRD
 * type, or -1 if the ARPHRD type is unknown
 */
libtrace_linktype_t arphrd_type_to_libtrace(unsigned int arphrd);

/** Converts a libtrace link type into an ARPHRD type.
 *
 * @param type		The libtrace link type to be converted
 * @return The ARPHRD type that is equivalent to the provided libtrace link
 * type, or -1 if the link type cannot be matched to an ARPHRD type
 */
unsigned int libtrace_to_arphrd_type(libtrace_linktype_t type);

/** Converts a libtrace packet to the Linux SLL type.
 *
 * @param packet	The packet to be promoted
 *
 * @note This will involve memcpy() so use sparingly.
 *
 * This function prepends a Linux SLL header to a packet so that we can store
 * direction tagging information.
 */
void promote_packet(libtrace_packet_t *packet);

/** Attempts to demote a packet by removing the first header.
 *
 * @param packet	The packet to be demoted
 * @return True if the packet was demoted, false otherwise.
 *
 * Essentially the opposite of promote_packet, except that it will also remove
 * an ATM header as well as Linux SLL.
 *
 */
bool demote_packet(libtrace_packet_t *packet);

/** Returns a pointer to the header following a Linux SLL header.
 *
 * @param link		A pointer to the Linux SLL header to be skipped
 * @param[out] arphrd_type	The arp hardware type of the packet
 * @param[out] next_header	The ethertype of the next header
 * @param[in,out] remaining	Updated with the number of captured bytes
 * 				remaining
 * @return A pointer to the header following the Linux SLL header, or NULL if
 * no subsequent header is present.
 *
 * Remaining must point to the number of bytes captured from the Linux SLL 
 * header and beyond.  It will be decremented by the number of bytes skipped
 * to find the payload.
 *
 * If the Linux SLL header is complete but there are zero bytes of payload 
 * after the end of the header, a pointer to where the payload would be is
 * returned and remaining will be set to zero. If the Linux SLL header is
 * incomplete (truncated), then NULL is returned and remaining will be set to
 * 0. Therefore, it is very important to check the value of remaining after
 * calling this function.
 */	
void *trace_get_payload_from_linux_sll(const void *link,
		uint16_t *arphrd_type, 
		uint16_t *next_header, 
		uint32_t *remaining);

/** Returns a pointer to the header following an ATM header.
 *
 * @param link		A pointer to the ATM header to be skipped
 * @param[out] type	The ethertype of the next header
 * @param[in,out] remaining	Updated with the number of captured bytes
 * 				remaining
 * @return A pointer to the header following the ATM header, or NULL if
 * no subsequent header is present.
 *
 * Remaining must point to the number of bytes captured from the ATM header
 * and beyond.  It will be decremented by the number of bytes skipped to find
 * the payload.
 *
 * If the ATM header is complete but there are zero bytes of payload 
 * after the end of the header, a pointer to where the payload would be is
 * returned and remaining will be set to zero. If the ATM header is
 * incomplete (truncated), then NULL is returned and remaining will be set to
 * 0. Therefore, it is very important to check the value of remaining after
 * calling this function.
 */	
DLLEXPORT void *trace_get_payload_from_atm(void *link, uint8_t *type, 
		uint32_t *remaining);


#ifdef HAVE_BPF
/* A type encapsulating a bpf filter
 * This type covers the compiled bpf filter, as well as the original filter
 * string
 *
 */

/** Internal representation of a BPF filter */
struct libtrace_filter_t {
	struct bpf_program filter;	/**< The BPF program itself */
	char * filterstring;		/**< The filter string */
	int flag;			/**< Indicates if the filter is valid */
	struct bpf_jit_t *jitfilter;
};
#else
/** BPF not supported by this system, but we still need to define a structure
 * for the filter */
struct libtrace_filter_t {};
#endif

/** Local definition of a PCAP header */
typedef struct libtrace_pcapfile_pkt_hdr_t {
	uint32_t ts_sec;	/* Seconds portion of the timestamp */
	uint32_t ts_usec;	/* Microseconds portion of the timestamp */
	uint32_t caplen;	/* Capture length of the packet */
	uint32_t wirelen;	/* The wire length of the packet */
} libtrace_pcapfile_pkt_hdr_t;

#ifdef HAVE_DAG
/** Constructor for the DAG format module */
void dag_constructor(void);
#endif
/** Constructor for the ERF format module */
void erf_constructor(void);
/** Constructor for the TSH format module */
void tsh_constructor(void);
/** Constructor for the Legacy DAG format module */
void legacy_constructor(void);
/** Constructor for the Linux Native format module */
void linuxnative_constructor(void);
/** Constructor for the PCAP format module */
void pcap_constructor(void);
/** Constructor for the PCAP File format module */
void pcapfile_constructor(void);
/** Constructor for the RT format module */
void rt_constructor(void);
/** Constructor for the DUCK format module */
void duck_constructor(void);
/** Constructor for the ATM Header format module */
void atmhdr_constructor(void);
#ifdef HAVE_BPF
/** Constructor for the BPF format module */
void bpf_constructor(void);
#endif
#if HAVE_DPDK
/** Constructor for Intels DPDK format module */
void dpdk_constructor(void);
#endif

/** Extracts the RadioTap flags from a wireless link header
 *
 * @param link		A pointer to the wireless link header
 * @param linktype	The link type of the wireless header
 * @param[out] flags	Space to store the extracted flags
 * @return True if libtrace was able to extract flags from the link header,
 * false otherwise.
 *
 * This function has been left internal because it is not portable across
 * drivers.
 */
bool trace_get_wireless_flags(void *link, libtrace_linktype_t linktype, uint8_t *flags);
#define TRACE_RADIOTAP_F_FCS 0x10
	
#ifdef __cplusplus
}
#endif

#endif /* LIBTRACE_INT_H */
