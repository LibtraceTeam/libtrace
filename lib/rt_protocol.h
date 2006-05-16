#ifndef _RT_PROTOCOL_H
#define _RT_PROTOCOL_H

#include "libtrace.h"
#include <time.h>

#define CAPTURE_PORT 3434
#define COLLECTOR_PORT 3435

#define RT_MAX_HDR_SIZE 256
#define MAX_SEQUENCE 2147483647 

#define RT_DATA_SIMPLE 1000
#define RT_DATA_PCAP 2000

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

/** Type field definitions */
enum rt_field_t {
 RT_HELLO       =1,     /**< Connection accepted */
 RT_START	=2,	/**< Request for data transmission to begin */
 RT_ACK		=3,	/**< Data acknowledgement */
 RT_STATUS	=4,	/**< Fifo status packet */
 RT_DUCK	=5,	/**< Dag duck info packet */
 RT_END_DATA	=6,	/**< Server is exiting message */
 RT_CLOSE	=7,	/**< Client is exiting message */
 RT_DENY_CONN	=8,	/**< Connection has been denied */
 RT_PAUSE	=9,	/**< Request server to suspend sending data */
 RT_PAUSE_ACK	=10,	/**< Server is paused message */
 RT_OPTION	=11,	/**< Option request */
 RT_KEYCHANGE	=12,	/**< Anonymisation key has changed */ 
 RT_DUCK_2_4	=13,	/**< Dag 2.4 Duck */
 RT_DUCK_2_5 	=14,	/**< Dag 2.5 Duck */
 
 RT_DATA_ERF		=RT_DATA_SIMPLE + TRACE_FORMAT_ERF, 
 RT_DATA_WAG		=RT_DATA_SIMPLE + TRACE_FORMAT_WAG, 
 RT_DATA_LEGACY_ATM	=RT_DATA_SIMPLE + TRACE_FORMAT_LEGACY_ATM, 
 RT_DATA_LEGACY_POS	=RT_DATA_SIMPLE + TRACE_FORMAT_LEGACY_POS, 
 RT_DATA_LEGACY_ETH	=RT_DATA_SIMPLE + TRACE_FORMAT_LEGACY_ETH, 
 RT_DATA_LINUX_NATIVE	=RT_DATA_SIMPLE + TRACE_FORMAT_LINUX_NATIVE,

 RT_DATA_PCAP_NULL		=RT_DATA_PCAP + TRACE_DLT_NULL,
 RT_DATA_PCAP_EN10MB		=RT_DATA_PCAP + TRACE_DLT_EN10MB,
 RT_DATA_PCAP_ATM_RFC1483	=RT_DATA_PCAP + TRACE_DLT_ATM_RFC1483,
 RT_DATA_PCAP_IEEE802_11	=RT_DATA_PCAP + TRACE_DLT_IEEE802_11,
 RT_DATA_PCAP_LINUX_SLL		=RT_DATA_PCAP + TRACE_DLT_LINUX_SLL,
 RT_DATA_PCAP_PFLOG		=RT_DATA_PCAP + TRACE_DLT_PFLOG,
 RT_LAST = 3000
};

typedef struct fifo_info {
        uint64_t in;
        uint64_t out;
        uint64_t ack;
        uint64_t length;
        uint64_t used;
} fifo_info_t;

/** RT packet header */
typedef struct rt_header {
	enum rt_field_t type;
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
        time_t        	Stat_Start;
	time_t		Stat_End;   
        uint32_t   	Set_Duck_Field;
} duck2_4_t;

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
        time_t          Stat_Start;
	time_t		Stat_End;
        uint64_t        Last_TSC;
} duck2_5_t;

/*
typedef struct rt_duck_2_4 {
	duck2_4_t duck;
} rt_duck_2_4_t;

typedef struct rt_duck_2_5 {
	duck2_5_t duck;
} rt_duck_2_5_t;
*/

#endif
