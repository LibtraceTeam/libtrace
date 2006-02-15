#ifndef _RT_PROTOCOL_H
#define _RT_PROTOCOL_H

#include "libtrace.h"

#define CAPTURE_PORT 3434
#define COLLECTOR_PORT 3435

// Type field definitions
#define RT_HELLO 	0	/* Connection accepted */
#define RT_DATA		1 	/* Libtrace data packet */
#define RT_START	2	/* Request for data transmission to begin */
#define RT_ACK		3	/* Data acknowledgement */
#define RT_STATUS	4	/* Fifo status packet */
#define RT_DUCK		5	/* Dag duck info packet */
#define RT_END_DATA	6	/* Server is exiting message */
#define RT_CLOSE	7	/* Client is exiting message */
#define RT_DENY_CONN	8	/* Connection has been denied */
#define RT_PAUSE	9	/* Request server to suspend sending data */
#define RT_PAUSE_ACK	10	/* Server is paused message */
#define RT_OPTION	11	/* Option request */

// Format field definitions
#define RT_FORMAT_ERF 		1
#define RT_FORMAT_PCAP		2
#define RT_FORMAT_WAG		3


// RT packet header
typedef struct rt_header {
	uint8_t type;
	uint16_t length;
} rt_header_t;

typedef struct rt_data {
	uint16_t format;
	char *data;
} rt_data_t;

typedef struct rt_hello {

} rt_hello_t;

typedef struct rt_start {

} rt_start_t;

typedef struct rt_ack {
	uint64_t timestamp;
} rt_ack_t;

typedef struct rt_status {
	tracefifo_state_t fifo_status;
} rt_status_t;

typedef struct rt_duck {
	//duckinf_t duck;
} rt_duck_t;

typedef struct rt_end_data {

} rt_end_data_t;

typedef struct rt_close {

} rt_close_t;


// Connection denied reasons
#define RT_DENY_WRAPPER 	1
#define RT_DENY_FULL		2
#define RT_DENY_AUTH		3

typedef struct rt_deny_conn {
	uint8_t reason;
} rt_deny_conn_t;


typedef struct rt_pause {

} rt_pause_t;

typedef struct rt_pause_ack {

} rt_pause_ack_t;

typedef struct rt_option {

} rt_option_t;


char *rt_deny_reason(uint8_t reason) {
	char *string = 0;

	switch(reason) {
		case RT_DENY_WRAPPER:
			string = "Rejected by TCP Wrappers";
			break;
		case RT_DENY_FULL:
			string = "Max connections reached on server";
			break;
		case RT_DENY_AUTH:
			string = "Authentication failed";
			break;
		default:
			string = "Unknown reason";
	}

	return string;
}

#endif
