#ifndef _RT_PROTOCOL_H
#define _RT_PROTOCOL_H

#include "libtrace.h"

#define CAPTURE_PORT 3434
#define COLLECTOR_PORT 3435

#define RT_MAX_HDR_SIZE 256
#define MAX_SEQUENCE 2147483647 

/* Type field definitions */
/* NOTE: RT_DATA should always be zero */
enum rt_field_t {
 RT_DATA	=0, 	/* Libtrace data packet */
 RT_HELLO       =1,     /* Connection accepted */
 RT_START	=2,	/* Request for data transmission to begin */
 RT_ACK		=3,	/* Data acknowledgement */
 RT_STATUS	=4,	/* Fifo status packet */
 RT_DUCK	=5,	/* Dag duck info packet */
 RT_END_DATA	=6,	/* Server is exiting message */
 RT_CLOSE	=7,	/* Client is exiting message */
 RT_DENY_CONN	=8,	/* Connection has been denied */
 RT_PAUSE	=9,	/* Request server to suspend sending data */
 RT_PAUSE_ACK	=10,	/* Server is paused message */
 RT_OPTION	=11	/* Option request */
};

typedef struct fifo_info {
        uint64_t in;
        uint64_t out;
        uint64_t ack;
        uint64_t length;
        uint64_t used;
} fifo_info_t;

/* RT packet header */
typedef struct rt_header {
	enum rt_field_t type;
	uint16_t length;
} rt_header_t;

typedef struct rt_data {
	uint16_t format;
	uint32_t sequence;
} rt_data_t;

/* TODO: Reorganise this struct once more hello info is added */
typedef struct rt_hello {
	uint8_t reliable;
} rt_hello_t;

typedef struct rt_start {

} rt_start_t;

typedef struct rt_ack {
	uint32_t sequence;
} rt_ack_t;

typedef struct rt_status {
	fifo_info_t fifo_status;
} rt_status_t;

typedef struct rt_duck {
	/*duckinf_t duck; */
} rt_duck_t;

typedef struct rt_end_data {

} rt_end_data_t;

typedef struct rt_close {

} rt_close_t;


/* Connection denied reasons */
enum rt_conn_denied_t {
 RT_DENY_WRAPPER 	=1,
 RT_DENY_FULL		=2,
 RT_DENY_AUTH		=3
};

typedef struct rt_deny_conn {
	enum rt_conn_denied_t reason;
} rt_deny_conn_t;


typedef struct rt_pause {

} rt_pause_t;

typedef struct rt_pause_ack {

} rt_pause_ack_t;

typedef struct rt_option {

} rt_option_t;




#endif
