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

#ifndef _RT_PROTOCOL_H
#define _RT_PROTOCOL_H

#include "libtrace.h"
#include <time.h>

/** @file
 *
 * @brief Header file containing definitions specific to the RT protocol that
 * can be used to transport captured packets over a network connection.
 *
 */

/** Default port for RT clients */
#define COLLECTOR_PORT 3435

/** Maximum size for the RT header */
#define RT_MAX_HDR_SIZE 256
/** Maximum sequence number for the RT protocol */
#define MAX_SEQUENCE 2147483647 

/* Procedure for adding new RT control types
 * -------------------------------------------
 *
 * Add type to the enum list
 * Add a struct below (even if it is empty - wrap it in an #if 0)
 * Update rt_get_capture_length
 * If type is intended to be sent TO clients, update rt_read_packet
 * 	Otherwise, update server implementations e.g. WDCAP
 *
 * Procedure for adding new RT data types
 * ----------------------------------------
 * 
 * If you are adding a new format:
 * 	RT_DATA_(new format) must be equal to RT_DATA_SIMPLE + 
 * 		TRACE_FORMAT_(new_format)
 * 	Add a new dummy trace type to the rt_format_t structure
 * 	Set the dummy trace to NULL in rt_init_input
 * 	Update rt_set_format
 *
 * If you are adding a new PCAP DLT type:
 * 	RT_DATA_PCAP_(new DLT) must be equal to RT_DATA_PCAP + (DLT value)
 * 	
 */

/** Fifo statistics reported by the RT_STATUS message */
typedef struct fifo_info {
        uint64_t in;		/**< The offset for the fifo write pointer */
        uint64_t out;		/**< The offset for the fifo read pointer */
        uint64_t ack;		/**< The offset for the fifo ACK pointer */
        uint64_t length;	/**< The total length of the fifo */
        uint64_t used;		/**< The amount of fifo space in use */
} fifo_info_t;

/** RT packet header */
typedef struct rt_header {
	/** The type of RT packet */
	libtrace_rt_types_t type;	
	/** The length of the packet (not including the RT header */
	uint16_t length;		
	/** The sequence number of the packet */
	uint32_t sequence;
} rt_header_t;

/* TODO: Reorganise this struct once more hello info is added */

/** RT Hello packet sub-header */
typedef struct rt_hello {
	/** Indicates whether the sender is acting in a reliable fashion, 
	 *  i.e. expecting acknowledgements */
	uint8_t reliable;	
} rt_hello_t;

#if 0
typedef struct rt_start {

} rt_start_t;
#endif

/** RT Ack sub-header */
typedef struct rt_ack {
	/** The sequence number of the last received RT packet */
	uint32_t sequence;
} rt_ack_t;

/** RT Status sub-header */
typedef struct rt_status {
	/** Statistics describing the current status of the sender fifo */
	fifo_info_t fifo_status;
} rt_status_t;

#if 0
typedef struct rt_duck {
	/*duckinf_t duck; */
} rt_duck_t;
#endif

#if 0
typedef struct rt_end_data {

} rt_end_data_t;
#endif

#if 0
typedef struct rt_close {

} rt_close_t; 
#endif

/** Reasons that an RT connection may be denied */
enum rt_conn_denied_t {
	/** The client failed a TCP wrapper check */
 	RT_DENY_WRAPPER 	=1,
	/** The server has reached the maximum number of client connections */
 	RT_DENY_FULL		=2,
	/** Client failed to correctly authenticate */
 	RT_DENY_AUTH		=3
};

/** RT Denied Connection sub-header */
typedef struct rt_deny_conn {
	/** The reason that the connection was denied */
	enum rt_conn_denied_t reason;
} rt_deny_conn_t;

#if 0
typedef struct rt_pause {

} rt_pause_t;
#endif

#if 0
typedef struct rt_pause_ack {

} rt_pause_ack_t;
#endif

#if 0
typedef struct rt_option {

} rt_option_t;
#endif

#if 0
typedef struct rt_keychange {
	
} rt_keychange_t;
#endif

/** RT meta-data sub-header */
typedef struct rt_metadata {
	/** Length of the label string that follows the header */
	uint32_t label_len;
	/** Length of the value string that follows the header */
	uint32_t value_len;
} rt_metadata_t ;

/** Specifications of duck structures - duck2_4 and duck2_5 match Endace's
 * duck_inf and duckinf_t respectively. Unfortunately, Endace don't exactly
 * make it clear what each value within the duck structure actually means.
 * Some are self-explanatory but I have no idea about the others so our own
 * documentation is a bit weak as a result */

/** DAG 2.4 DUCK */
typedef struct duck2_4 {
	uint32_t   	Command;
	uint32_t 	Config;
	uint32_t 	Clock_Inc;
	uint32_t	Clock_Wrap;
	uint32_t	DDS_Rate;
        uint32_t   	Crystal_Freq;
        uint32_t   	Synth_Freq; 
	uint32_t	Sync_Rate;
        uint64_t 	Last_Ticks;
        uint32_t   	Resyncs;
        uint32_t   	Bad_Diffs;
	uint32_t 	Bad_Offs;
	uint32_t	Bad_Pulses;
        uint32_t   	Worst_Error;
	uint32_t	Worst_Off;
        uint32_t   	Off_Limit;
	uint32_t	Off_Damp;
        uint32_t   	Pulses;
	uint32_t	Single_Pulses_Missing;
	uint32_t	Longest_Pulse_Missing;
        uint32_t   	Health;
	uint32_t	Sickness;
        int32_t        	Error;
	int32_t		Offset;
        uint32_t       	Stat_Start;
	uint32_t	Stat_End;   
        uint32_t   	Set_Duck_Field;
} PACKED duck2_4_t;

/** DAG 2.5 DUCK */
typedef struct duck2_5 {
        uint32_t        Crystal_Freq;
        uint32_t        Synth_Freq;
        uint64_t        Last_Ticks;
        uint32_t        Resyncs;
        uint32_t        Bad_Pulses;
        uint32_t        Worst_Freq_Err;
	uint32_t	Worst_Phase_Err;
        uint32_t        Health_Thresh;
        uint32_t        Pulses;
	uint32_t	Single_Pulses_Missing;
	uint32_t	Longest_Pulse_Missing;
        uint32_t        Health;
	uint32_t	Sickness;
        int32_t         Freq_Err;
	int32_t		Phase_Err;
        uint32_t        Set_Duck_Field;
        uint32_t        Stat_Start;
	uint32_t	Stat_End;
        uint64_t        Last_TSC;
} PACKED duck2_5_t;

typedef struct duck5_0 {
        int64_t         Phase_Correction;
        uint64_t        Last_Ticks;
        uint64_t        Last_TSC;
	/* XXX Stat_Start and Stat_End are time_t in dagioctl.h, which means 
	 * they could in theory be 32 or 64 bit depending on the architecture 
	 * when capturing. I'm going to assume 5.0 era DAG captures are taking
	 * place on a 64 bit arch, rather than have to deal with the varying
	 * sizes (especially given nobody really uses DUCK these days).
	 */
        uint64_t        Stat_Start, Stat_End;
        uint32_t        Crystal_Freq;
        uint32_t        Synth_Freq;
        uint32_t        Resyncs;
        uint32_t        Bad_Pulses;
        uint32_t        Worst_Freq_Err, Worst_Phase_Err;
        uint32_t        Health_Thresh;
        uint32_t        Pulses, Single_Pulses_Missing, Longest_Pulse_Missing;
        uint32_t        Health, Sickness;
        int32_t         Freq_Err, Phase_Err;
        uint32_t        Set_Duck_Field;
} PACKED duck5_0_t;

/*
typedef struct rt_duck_2_4 {
	duck2_4_t duck;
} rt_duck_2_4_t;

typedef struct rt_duck_2_5 {
	duck2_5_t duck;
} rt_duck_2_5_t;
*/

#endif
