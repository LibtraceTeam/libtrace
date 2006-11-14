#ifndef _RT_PROTOCOL_H
#define _RT_PROTOCOL_H

#include "libtrace.h"
#include <time.h>

#define CAPTURE_PORT 3434
#define COLLECTOR_PORT 3435

#define RT_MAX_HDR_SIZE 256
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

typedef struct fifo_info {
        uint64_t in;
        uint64_t out;
        uint64_t ack;
        uint64_t length;
        uint64_t used;
} fifo_info_t;

/** RT packet header */
typedef struct rt_header {
	libtrace_rt_types_t type;
	uint16_t length;
	uint32_t sequence;
} rt_header_t;

/* TODO: Reorganise this struct once more hello info is added */
/** RT Hello packet sub-header */
typedef struct rt_hello {
	uint8_t reliable;
} rt_hello_t;

#if 0
typedef struct rt_start {

} rt_start_t;
#endif

/** RT Ack sub-header */
typedef struct rt_ack {
	uint32_t sequence;
} rt_ack_t;

/** RT Status sub-header */
typedef struct rt_status {
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

/** Connection denied reasons */
enum rt_conn_denied_t {
 RT_DENY_WRAPPER 	=1,
 RT_DENY_FULL		=2,
 RT_DENY_AUTH		=3
};

/** RT Denied Connection sub-header */
typedef struct rt_deny_conn {
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

/** Specifications of duck structures - duck2_4 and duck2_5 match Endace's
 * duck_inf and duckinf_t respectively */

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

/*
typedef struct rt_duck_2_4 {
	duck2_4_t duck;
} rt_duck_2_4_t;

typedef struct rt_duck_2_5 {
	duck2_5_t duck;
} rt_duck_2_5_t;
*/

#endif
