#ifndef _WAG_H_
#define _WAG_H_

struct wag_event_t {
	uint32_t length;
	uint32_t timestamp_hi;
	uint32_t timestamp_lo;
	uint32_t type;
	uint32_t seq_num;
	uint8_t payload[];
};

struct wag_data_event_t {
	uint32_t rx_params;
	uint32_t rx_rssi;
	uint32_t frame_length;
	uint8_t data[];
};

struct ieee_802_11_header {
	uint8_t      protocol:2;
	uint8_t	     type:2;
	uint8_t      subtype:4;
	uint8_t	     to_ds:1;
	uint8_t	     from_ds:1;
	uint8_t	     more_frag:1;
	uint8_t	     retry:1;
	uint8_t	     power:1;
	uint8_t	     more_data:1;
	uint8_t	     wep:1;
	uint8_t	     order:1;
	uint16_t     duration;
	uint8_t      mac1[6];
	uint8_t      mac2[6];
	uint8_t      mac3[6];
	uint16_t     SeqCtl;
	uint8_t      mac4[6];
	uint8_t	     data[];
};

struct ieee_802_11_payload {
	uint16_t     type;
	uint8_t	     data[];
};

#endif
