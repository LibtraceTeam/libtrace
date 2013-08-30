/* 
 * 802.11 libpacketdump decoder
 * 
 * Originally based on "wagdump" (c) 2005 Dean Armstrong
 *
 * This decoder will attempt to do it's best at decoding the frame formats
 * defined in the following standards. Not all fields are decoded, but they
 * are at least acknowledged as being present. 
 *
 *  802.11
 *  802.11b
 *  802.11d - operation in multiple regulatory domains
 *  802.11e - wireless multimedia extensions
 *  802.11g
 *  802.11h - power management
 *  802.11i - MAC security enhancements 
 *
 *  It will also attempt to decode vendor specific Information Elements
 *  if possible.
 *
 *  (c) 2006 Scott Raynel <scottraynel@gmail.com>
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>
#include "libpacketdump.h"
#include "libtrace.h"

typedef struct ieee80211_frame_control {
# if __BYTE_ORDER == __LITTLE_ENDIAN	
	uint8_t		version:2;
	uint8_t		type:2;
	uint8_t		subtype:4;
	uint8_t		to_ds:1;
	uint8_t		from_ds:1;
	uint8_t		more_frag:1;
        uint8_t		retry:1;
        uint8_t		power:1;
        uint8_t		more_data:1;
        uint8_t		wep:1;
        uint8_t		order:1;
# elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t		subtype:4;
	uint8_t		type:2;
	uint8_t		version:2;
        uint8_t		order:1;
        uint8_t		wep:1;
        uint8_t		more_data:1;
        uint8_t		power:1;
        uint8_t		retry:1;
	uint8_t		more_frag:1;
	uint8_t		from_ds:1;
	uint8_t		to_ds:1;
#else
#	error "Adjust your <bits/endian.h> defines"
# endif	
} __attribute__ ((__packed__)) ieee80211_frame_control;

typedef struct ieee80211_ctrl_frame_1addr {
	ieee80211_frame_control	ctl;
        uint16_t     duration;
        uint8_t      addr1[6];
} __attribute__ ((__packed__)) ieee80211_ctrl_frame_1addr;

typedef struct ieee80211_ctrl_frame_2addr {
	ieee80211_frame_control	ctl;
        uint16_t     duration;
        uint8_t      addr1[6];
        uint8_t      addr2[6];
} __attribute__ ((__packed__)) ieee80211_ctrl_frame_2addr;

typedef struct ieee80211_data_frame_3 {
	ieee80211_frame_control ctl;
	uint16_t	duration;
	uint8_t		addr1[6];
	uint8_t		addr2[6];
	uint8_t		addr3[6];
	uint16_t	seq_ctrl;
} __attribute__ ((__packed__)) ieee80211_data_frame_3;

typedef struct ieee80211_data_frame {
	ieee80211_frame_control ctl;
	uint16_t	duration;
	uint8_t		addr1[6];
	uint8_t		addr2[6];
	uint8_t		addr3[6];
	uint16_t	seq_ctrl;
	uint8_t		addr4[6];
} __attribute__ ((__packed__)) ieee80211_data_frame;

typedef struct ieee80211_qos_data_frame {
	ieee80211_frame_control ctl;
	uint16_t	duration;
	uint8_t		addr1[6];
	uint8_t		addr2[6];
	uint8_t		addr3[6];
	uint16_t	seq_ctrl;
	uint8_t		addr4[6];
	uint16_t	qos;
} __attribute__ ((__packed__)) ieee80211_qos_data_frame;

typedef struct ieee80211_mgmt_frame {
	ieee80211_frame_control ctl;
	uint16_t	duration;
	uint8_t		addr1[6];
	uint8_t		addr2[6];
	uint8_t		addr3[6];
	uint16_t	seq_ctrl;
} __attribute__ ((__packed__)) ieee80211_mgmt_frame;

typedef struct ieee80211_payload {
	uint16_t	ethertype;
	uint8_t		payload[1];
} __attribute__ ((__packed__)) ieee80211_payload;

static char *macaddr(uint8_t mac[]) {
	static char ether_buf[18] = {0, };
	trace_ether_ntoa(mac, ether_buf);
	return ether_buf;
}

typedef struct ieee80211_capinfo {
#if __BYTE_ORDER == __LITTLE_ENDIAN 
	uint8_t	ess:1;
	uint8_t	ibss:1;
	uint8_t	cf_pollable:1;
	uint8_t	cf_poll_req:1;
	uint8_t	privacy:1;
	uint8_t	short_preamble:1;
	uint8_t	pbcc:1;
	uint8_t	channel_agility:1;
	uint8_t	spectrum_mgmt:1;
	uint8_t	qos:1;
	uint8_t	short_slot_time:1;
	uint8_t	apsd:1;
	uint8_t	res1:1;
	uint8_t	dsss_ofdm:1;
	uint8_t	delayed_block_ack:1;
	uint8_t	immediate_block_ack:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t	channel_agility:1;
	uint8_t	pbcc:1;
	uint8_t	short_preamble:1;
	uint8_t	privacy:1;
	uint8_t	cf_poll_req:1;
	uint8_t	cf_pollable:1;
	uint8_t	ibss:1;
	uint8_t	ess:1;
	uint8_t	immediate_block_ack:1;
	uint8_t	delayed_block_ack:1;
	uint8_t	dsss_ofdm:1;
	uint8_t	res1:1;
	uint8_t	apsd:1;
	uint8_t	short_slot_time:1;
	uint8_t	qos:1;
	uint8_t	spectrum_mgmt:1;
#else
# error "Unknown byte order -- please check <bits/endian.h>"
#endif
} __attribute__ ((__packed__)) ieee80211_capinfo;

typedef struct ieee80211_beacon {
	ieee80211_mgmt_frame mgmt;
	uint64_t	ts;
	uint16_t	interval;
	ieee80211_capinfo capinfo;
} __attribute__ ((__packed__)) ieee80211_beacon;

typedef struct ieee80211_assoc_req { 
	ieee80211_mgmt_frame mgmt;
	ieee80211_capinfo capinfo;
	uint16_t	listen_interval;
} __attribute__ ((__packed__)) ieee80211_assoc_req;

typedef struct ieee80211_assoc_resp {
	ieee80211_mgmt_frame mgmt;
	ieee80211_capinfo capinfo;
	uint16_t	status_code;
	uint16_t	assoc_id;
} __attribute__ ((__packed__)) ieee80211_assoc_resp;

typedef struct ieee80211_reassoc_req {
	ieee80211_mgmt_frame mgmt;
	ieee80211_capinfo capinfo;
	uint16_t	listen_interval;
	uint8_t		current_address[6];
} __attribute__ ((__packed__)) ieee80211_reassoc_req;

typedef struct ieee80211_auth {
	ieee80211_mgmt_frame mgmt;
	uint16_t	auth_algo_num;
	uint16_t	auth_trans_seq_num;
	uint16_t	status_code;
} __attribute__ ((__packed__)) ieee80211_auth;


typedef struct ieee80211_ie {
	uint8_t		id;
	uint8_t		length;
} __attribute__ ((__packed__)) ieee80211_ie;

/*
 * Takes a vendor IE and decodes it
 */
static void decode_80211_vendor_ie(ieee80211_ie *ie) {
	uint8_t *data = (uint8_t *) ((char *)ie + sizeof(ieee80211_ie));
	uint32_t ie_oui;	
	printf("  Vendor Private Information Element\n");
	if (ie->length <= 3) return;
	ie_oui = (data[0] << 16) | (data[1] << 8) | data[2];
	switch(ie_oui) {
		case 0x0050f2:
			printf("   Atheros 802.11i/WPA IE\n");
			break;
		case 0x00037f:
			printf("   Atheros Advanced Capability IE\n");
			break;
		default:
			printf("   Unknown Vendor OUI (0x%06x)\n", ie_oui);
			break;
	}

}

/* 
 * Takes a pointer to the start of the IEs in a beacon and the
 * length remaining and decodes the IEs.
 */
static void decode_80211_information_elements(const char *pkt, unsigned len) {
	ieee80211_ie *ie;
	int i = 0;
	const uint8_t * data;
	uint8_t bmap_offset;
	while (len >= sizeof(ieee80211_ie)) {
		ie = (ieee80211_ie *) pkt;
		
		if ( len < ( sizeof(ieee80211_ie) + ie->length)) {
			printf("  [Truncated]\n");
			return;
		}
		
		data = (( const unsigned char *)pkt + sizeof (ieee80211_ie));
		
		switch (ie->id) {
			case 0:
				printf("  SSID = ");
				for (i = 0; i < ie->length; i++) 
					printf("%c", data[i]);
				printf("\n");
				break;
			case 1:
				printf("  Supported Rates (Kbit/s):\n   ");
				/* NB: the MSB of each field will be set
				 * if the rate it describes is part of the
				 * basic rate set, hence the AND */
				for (i = 0; i < ie->length; i++) {
					printf("%u, ", 
						( (data[i]&0x7F) * 500));

				}
				printf("%c%c\n", 0x8, 0x8);
				break;
			case 3:
				printf("  DSSS Channel = ");
				printf("%u\n", *data);
				break;
			case 5:
				printf("  Traffic Indication Message:\n");
				printf("   DTIM Count = %u, ", *data);
				data++;
				printf("DTIM Period = %u\n", *data);
				data++;
				printf("   Broadcast/Multicast waiting = %s\n", 
					(*data) & 0x01 ? "Yes\0" : "No\0");
				bmap_offset = ((*data) & 0xFE) >> 1;
				data++;
				if ((ie->length == 4) && ( *data == 0)) {
					printf("   No traffic waiting for stations\n");
					break;
				}
				
				printf("   Traffic waiting for AssocIDs: ");
				for (i = 0; i < (ie->length - 3); i++) {
					int j;
					for (j = 0; j < 8; j++) {
						if (data[i] & (1 << j)) {
							printf("%u ", (bmap_offset + i + 1) * 8 + j);
						}
					}
				}		
				printf("\n");
						
				break;
			case 7:
				printf("  802.11d Country Information:\n");
				printf("   ISO 3166 Country Code: %c%c\n", data[0], data[1]);
				printf("   Regulatory Operating Environment: ");
				if (data[2] == ' ') printf("Indoor/Outdoor\n");
				else if (data[2] == 'O') printf("Outdoor only\n");
				else if (data[2] == 'I') printf("Indoor only\n");
				else printf("Unknown, code = %c\n", data[2]);
				data += sizeof(uint8_t) * 3;
				for (i = 0; i < ((ie->length - 3) / 3); i++) {
					printf("   First Channel: %u, Num Channels: %u, Max Tx Power %idBm\n",
							data[0], data[1], (int8_t) data[2]);
					data += sizeof(uint8_t) * 3;
				}
				
				break;
			case 11:
				printf("  802.11e QBSS Load\n");
				break;
			case 12:
				printf("  802.11e EDCA Parameter\n");
				break;
			case 13:
				printf("  802.11e TSPEC\n");
				break;
			case 14:
				printf("  802.11e TCLAS\n");
				break;
			case 15:
				printf("  802.11e Schedule\n");
				break;
			case 16:
				printf("  Authentication Challenge Text\n");
				break;
			case 32:
				printf("  802.11h Power Contraint\n");
				printf("   Local Power Contraint = %udB\n", data[0]);
				break;
			case 33:
				printf("  802.11h Power Capability\n");
				printf("   Minimum Transmit Power Capability = %idBm\n", (int8_t)data[0]);
				printf("   Maximum Transmit Power Capability = %idBm\n", (int8_t)data[1]);
				break;
			case 34:
				printf("  802.11h Transmit Power Control Request\n");
				break;
			case 35:
				printf("  802.11h Transmit Power Control Report\n");
				printf("   Transmit Power = %idBm\n", (int8_t)data[0]);
				printf("   Link Margin = %idB\n", (int8_t)data[1]);
				break;
			case 36:
				printf("  802.11h Supported Channels\n");
				for(i = 0; i < (ie->length / 2); i++) {
					printf("   First Channel = %u, Num Channels = %u\n", data[0], data[1]);
					data += 2;
				}
				break;
			case 37:
				printf("  802.11h Channel Switch Announcement\n");
				printf("   New Channel Number = %u\n", data[1]);
				printf("   Target Beacon Transmission Times untill switch = %u\n", data[2]);
				if (data[0]) printf("   Don't transmit more frames until switch occurs\n");
				break;
			case 38:
				printf("  802.11h Measurement Request\n");
				break;
			case 39:
				printf("  802.11h Measurement Report\n");
				break;
			case 40:
				printf("  802.11h Quiet\n");
				break;
			case 41:
				printf("  802.11h IBSS DFS\n");
				break;
			case 42:
				printf("  802.11g ERP Information\n");
				if(data[0] & 0x80) printf("   NonERP STAs are present in this BSS\n");
				if(data[0] & 0x40) printf("   Use Protection Mechanism\n");
				if(data[0] & 0x20) printf("   Do not use short preamble\n");
				break;
			case 43:
				printf("  802.11e TS Delay\n");
				break;
			case 44:
				printf("  802.11e TCLAS Processing\n");
				break;
			case 46:
				printf("  802.11e QoS Capability\n");
				break;
			case 48:
				printf("  802.11i RSN:\n");
				break;
			case 50:
				printf("  802.11g Extended Supported Rates (Kbit/s)\n   ");
				for(i = 0; i < ie->length; i++) 
					printf("%u, ", data[i] * 500);
				printf("%c%c\n", (char) 8, (char) 8);		
				break;
				
			case 221:
				decode_80211_vendor_ie(ie);
				break;
			default:
				printf("  Unknown IE Element ID, 0x%02x\n", ie->id);
		}
		len -= sizeof(ieee80211_ie) + ie->length;
		pkt = ((char *)pkt + sizeof(ieee80211_ie) + ie->length);
	}
}

static
void ieee80211_print_reason_code(uint16_t code) {
	switch (code) {
		case 0: printf("Reserved"); break;
		case 1: printf("Unspecified Reason"); break;
		case 2: printf("Previous authentication no longer valid"); break;
		case 3: printf("Deauthenticated because sending station is leaving or has left IBSS or BSS"); break;
		case 4: printf("Disassociated due to inactivity"); break;
		case 5: printf("Disassociated because AP is unable to handle all currently associated stations"); break;
		case 6: printf("Class 2 frame received from nonauthenticated station"); break;
		case 7: printf("Class 3 frame received from nonassociated station"); break;
		case 8: printf("Disassociated because AP is leaving (or has left) BSS"); break;
		case 9: printf("Station requesting (re)association is not authenticated with responding station"); break;
		default: printf("Unknown reason code: %u\n", code);
	}
}

static 
void ieee80211_print_status_code(uint16_t code) {
	switch (code) {
		case 0: printf("Successful"); break;
		case 1: printf("Unspecified failure"); break;
		case 10: printf("Cannot support all requested capabilities in the Capability Information field"); break;
		case 11: printf("Reassociation denied due to inablity to confirm that association exists"); break;
		case 12: printf("Association denied due to reason outside the scope of this standard"); break;
		case 13: printf("Responding station does not support the specified authentication algorithm"); break;
		case 14: printf("Received an Authentication frame with authentication transaction sequence number outside of expected sequence"); break;
		case 15: printf("Authentication rejected because of channege failure"); break;
		case 16: printf("Authentication rejected due to timeout waiting for next frame in sequence"); break;
		case 17: printf("Association denied because AP is unable to handle additional associated stations"); break;
		case 18: printf("Association denied due to requesting station not supporting all of the data rates in the BSSBasicRates parameter"); break;
		default: printf("Unknown status code: %u", code);
	}
}

/* Decodes a capability info field */
static void decode_80211_capinfo(ieee80211_capinfo *c) {
	printf(" 802.11MAC: Capability Info:");
	if (c->ess) printf(" ESS");
	if (c->ibss) printf(" IBSS");
	if (c->cf_pollable) printf(" CF-POLLABLE");
	if (c->cf_poll_req) printf(" CF-POLL-REQ");
	if (c->privacy) printf(" PRIVACY");
	if (c->short_preamble) printf(" SHORT-PREAMBLE");
	if (c->pbcc) printf (" PBCC");
	if (c->channel_agility) printf (" CHANNEL-AGILITY");
	if (c->spectrum_mgmt) printf( " SPECTRUM-MGMT");
	if (c->qos) printf(" QoS");
	if (c->short_slot_time) printf (" SHORT-SLOT-TIME");
	if (c->apsd) printf(" APSD");
	if (c->dsss_ofdm) printf (" DSSS-OFDM");
	if (c->delayed_block_ack) printf(" DELAYED-BLK-ACK");
	if (c->immediate_block_ack) printf(" IMMEDIATE-BLK-ACK");
	printf("\n");
}
	
/* Decodes a beacon (or a probe response) */
static void decode_80211_beacon(const char *pkt, unsigned len) {
	ieee80211_beacon *b = (ieee80211_beacon *)pkt;
	if (len < sizeof(ieee80211_beacon)) {
		printf(" 802.11MAC: [Truncated]\n");
		return;
	}
	
	printf(" 802.11MAC: Timestamp = %" PRIu64 "\n", b->ts);
	printf(" 802.11MAC: Beacon Interval = %u\n", b->interval);
	decode_80211_capinfo(&b->capinfo);
	printf(" 802.11MAC: Information Elements:\n");
	decode_80211_information_elements((char *) pkt + sizeof(ieee80211_beacon), len - sizeof(ieee80211_beacon));		
}

static void decode_80211_assoc_request(const char *pkt, unsigned len) {
	ieee80211_assoc_req *a = (ieee80211_assoc_req *) pkt;
	
	if (len < sizeof(ieee80211_assoc_req)) {
		printf(" [Truncated association request]\n");
		return;
	}

	decode_80211_capinfo(&a->capinfo);
	printf(" 802.11MAC: Listen Interval = %u beacon intervals\n", a->listen_interval);
	printf(" 802.11MAC: Information Elements:\n");
	decode_80211_information_elements((char *)pkt + sizeof(ieee80211_assoc_req), len - sizeof(ieee80211_assoc_req));
}

static void decode_80211_assoc_response(const char *pkt, unsigned len) {
	ieee80211_assoc_resp *r = (ieee80211_assoc_resp *) pkt;

	if (len < sizeof(ieee80211_assoc_resp)) {
		printf(" [Truncated association response]\n");
		return;
	}
	decode_80211_capinfo(&r->capinfo);
	printf(" 802.11MAC: Status Code = ");
	ieee80211_print_status_code(r->status_code);
	/* AID has two most significant bits set to 1 */
	printf("\n 802.11MAC: Association ID = %u\n", r->assoc_id & 0x3FFF);
	decode_80211_information_elements((char *)pkt + sizeof(ieee80211_assoc_resp), len-sizeof(ieee80211_assoc_resp));
}
	
static void decode_80211_reassoc_request(const char *pkt, unsigned len) {
	ieee80211_reassoc_req *r = (ieee80211_reassoc_req *) pkt;

	if (len < sizeof(ieee80211_reassoc_req)) {
		printf(" [Truncated reassociation request]\n");
		return;
	}
	decode_80211_capinfo(&r->capinfo);
	printf(" 802.11MAC: Listen Interval = %u beacon intervals\n", r->listen_interval);
	printf(" 802.11MAC: Current AP address = %s\n", macaddr(r->current_address));
	printf(" 802.11MAC: Information Elements:\n");
	decode_80211_information_elements((char *)pkt + sizeof(ieee80211_reassoc_req), len - sizeof(ieee80211_reassoc_req));
}

static void decode_80211_authentication_frame(const char *pkt, unsigned len) {
	ieee80211_auth *auth = (ieee80211_auth *)pkt;
	if(len < sizeof(ieee80211_auth)) {
		printf(" [Truncated authentication frame]\n");
		return;
	}
	printf(" 802.11MAC: Authentication algorithm number = %u\n", auth->auth_algo_num);
	printf(" 802.11MAC: Authentication transaction sequence number = %u\n", auth->auth_trans_seq_num);
	printf(" 802.11MAC: Status Code = ");
	ieee80211_print_status_code(auth->status_code);
	printf("\n 802.11MAC: Information Elements:\n");
	decode_80211_information_elements((char *)pkt + sizeof(ieee80211_auth), len - sizeof(ieee80211_auth));

}

static void decode_80211_mgmt(const char *pkt, unsigned len) {
	ieee80211_mgmt_frame *mgmt = (ieee80211_mgmt_frame *)pkt;
	const char *data;
	
	printf(" 802.11MAC: Management frame: ");
	
	if (len < sizeof(ieee80211_mgmt_frame)) {
		printf("[Truncated]\n");
		return;
	}

	switch (mgmt->ctl.subtype) {
		case 0: printf("association request"); break;
		case 1: printf("association response"); break;
		case 2: printf("reassociation request"); break;
		case 3: printf("reassociation response"); break;
		case 4: printf("probe request"); break;
		case 5: printf("probe response"); break;
		case 8: printf("beacon"); break;
		case 9: printf("ATIM"); break;
		case 10: printf("disassociation"); break;
		case 11: printf("authentication"); break;
		case 12: printf("deauthentication"); break;
		case 13: printf("action"); break;
		default: printf("RESERVED"); break;
	}
	
	printf("\n 802.11MAC: Duration = %u us\n", mgmt->duration);
	printf(" 802.11MAC: DA       = %s\n", macaddr(mgmt->addr1));
	printf(" 802.11MAC: SA       = %s\n", macaddr(mgmt->addr2));
	printf(" 802.11MAC: BSSID    = %s\n", macaddr(mgmt->addr3));
	printf(" 802.11MAC: fragment no. = %u, sequence no. = %u\n",
			(mgmt->seq_ctrl & 0x000F) ,
			(mgmt->seq_ctrl & 0xFFF0) >> 4);

	switch (mgmt->ctl.subtype) {
		case 0:
			decode_80211_assoc_request(pkt, len);
			break;	
		case 1:
			decode_80211_assoc_response(pkt, len);
			break;
		case 2:
			decode_80211_reassoc_request(pkt, len);
			break;
		case 3:
			/* Reassoc response == assoc response */
			decode_80211_assoc_response(pkt, len);
			break;
		case 4:
			decode_80211_information_elements((char *)pkt + sizeof(ieee80211_mgmt_frame), len - sizeof(ieee80211_mgmt_frame));
			break;
		case 5:
			/* Probe response == beacon frame */
			decode_80211_beacon(pkt, len);
			break;
		case 8:
			decode_80211_beacon(pkt, len);
			break;
		case 10:
			data = (pkt + sizeof(ieee80211_mgmt_frame));
			printf(" 802.11MAC: Reason Code = ");
			ieee80211_print_reason_code((uint16_t) ((data[0] << 8) | (data[1])));
			printf("\n");
			break;
						    
		case 11:
			decode_80211_authentication_frame(pkt, len);
			break;
		case 12:
			data = (pkt + sizeof(ieee80211_mgmt_frame));
			printf(" 802.11MAC: Reason Code = ");
			ieee80211_print_reason_code((uint16_t) ((data[0] << 8) | (data[1])));
			printf("\n");
			break;
		default:
			printf(" 802.11MAC: Subtype %u decoder not implemented\n", mgmt->ctl.subtype);
	}

	printf("\n");

}

static void decode_80211_ctrl(const char *pkt, unsigned len) {
	ieee80211_ctrl_frame_1addr *ctrl1 = (ieee80211_ctrl_frame_1addr *) pkt;
	ieee80211_ctrl_frame_2addr *ctrl2 = (ieee80211_ctrl_frame_2addr *) pkt;
	printf(" 802.11MAC: Control frame: ");
	
	if (len < sizeof(ieee80211_ctrl_frame_1addr)) {
		printf("[Truncated]\n");
		return;
	}
	
	switch (ctrl1->ctl.subtype) {
		case 8: 
			printf("BlockAckReq\n"); 
			break;
		case 9: 
			printf("BlockAck\n"); 
			break;
		case 10: 
			printf("PS-Poll\n"); 
			printf(" 802.11MAC: AID = 0x%04x\n", ntohs(ctrl1->duration));
			printf(" 802.11MAC: BSSID = %s\n", macaddr(ctrl1->addr1));
			break;
		case 11:
			printf("RTS\n");
 
			if (len < sizeof(ieee80211_ctrl_frame_2addr)) {
				printf("[Truncated]\n");
				return;
			}

			printf(" 802.11MAC: RA = %s\n", macaddr(ctrl2->addr1));
			printf(" 802.11MAC: TA = %s\n", macaddr(ctrl2->addr2));
			break;
		case 12: 
			printf("CTS\n"); 
			printf(" 802.11MAC: RA = %s\n", macaddr(ctrl1->addr1));
			break;
		case 13:
			printf("ACK\n"); 
			printf(" 802.11MAC: RA = %s\n", macaddr(ctrl1->addr1));
			break;
		case 14:
			printf("CF-End\n"); 

			if (len < sizeof(ieee80211_ctrl_frame_2addr)) {
				printf("[Truncated]\n");
				return;
			}

			printf(" 802.11MAC: RA = %s\n", macaddr(ctrl2->addr1));
			printf(" 802.11MAC: BSSID = %s\n", macaddr(ctrl2->addr2));
			break;
		case 15:
			printf("CF-End + CF-Ack\n"); 

			if (len < sizeof(ieee80211_ctrl_frame_2addr)) {
				printf("[Truncated]\n");
				return;
			}

			printf(" 802.11MAC: RA = %s\n", macaddr(ctrl2->addr1));
			printf(" 802.11MAC: BSSID = %s\n", macaddr(ctrl2->addr2));
			break;
		default:
			printf("RESERVED"); 
			break;
	}

}

static void decode_80211_data(const char *pkt, unsigned len) {
	ieee80211_data_frame *data = (ieee80211_data_frame *) pkt;
	ieee80211_qos_data_frame *qos = (ieee80211_qos_data_frame *)pkt;
	ieee80211_payload *pld; 
	uint32_t hdrlen = 0;
	
	printf(" 802.11MAC: Data frame: ");
	
	if (len < sizeof(ieee80211_data_frame_3)) {
		printf("[Truncated]\n");
		return;
	}

	switch (data->ctl.subtype) {
		case 0: printf("Data"); break;
		case 1: printf("Data + CF-Ack"); break;
		case 2: printf("Data + CF-Poll"); break;
		case 3: printf("Data + CF-Ack + CF-Poll"); break;
		case 4: printf("Null (no data)"); break;
		case 5: printf("CF-Ack (no data)"); break;
		case 6: printf("CF-Poll (no data)"); break;
		case 7: printf("CF-Ack + CF-Poll (no data)"); break;
		case 8: printf("QoS Data"); break;
		case 9: printf("QoS Data + CF-Ack"); break;
		case 10: printf("QoS Data + CF-Poll"); break;
		case 11: printf("QoS Data + CF-Ack + CF-Poll"); break;
		case 12: printf("QoS Null (no data)"); break;
			 /* subtype 13 is reserved */
		case 14: printf("QoS CF-Poll (no data)"); break;
		case 15: printf("Qos CF-Ack + CF-Poll (no data)"); break;

		default: printf("RESERVED"); break;
	}

	printf("\n 802.11MAC: duration = %u us\n", data->duration);
	printf(" 802.11MAC: fragment no. = %u, sequence no. = %u\n",
			(data->seq_ctrl & 0x000F) ,
			(data->seq_ctrl & 0xFFF0) >> 4);

	hdrlen = sizeof(ieee80211_data_frame_3);
	
	if (! data->ctl.from_ds && ! data->ctl.to_ds) {
		printf(" 802.11MAC: DA      = %s\n", macaddr(data->addr1));
		printf(" 802.11MAC: SA      = %s\n", macaddr(data->addr2));
		printf(" 802.11MAC: BSSID   = %s\n", macaddr(data->addr3));
	} else if ( ! data->ctl.from_ds && data->ctl.to_ds) {
		printf(" 802.11MAC: DA      = %s\n", macaddr(data->addr3));
		printf(" 802.11MAC: SA      = %s\n", macaddr(data->addr2));
		printf(" 802.11MAC: BSSID   = %s\n", macaddr(data->addr1));
	} else if ( data->ctl.from_ds && ! data->ctl.to_ds) {
		printf(" 802.11MAC: DA      = %s\n", macaddr(data->addr1));
		printf(" 802.11MAC: SA      = %s\n", macaddr(data->addr3));
		printf(" 802.11MAC: BSSID   = %s\n", macaddr(data->addr2));
	} else {
		/* Check to make sure we have a four-address frame first */
		if (len < sizeof(ieee80211_data_frame)) {
			printf(" 802.11MAC: [Truncated]\n");
			return;
		}
		printf(" 802.11MAC: DA      = %s\n", macaddr(data->addr3));
		printf(" 802.11MAC: SA      = %s\n", macaddr(data->addr4));
		printf(" 802.11MAC: TA      = %s\n", macaddr(data->addr2));
		printf(" 802.11MAC: RA      = %s\n", macaddr(data->addr1));
		hdrlen = sizeof(ieee80211_data_frame); /* 4 addr header */
	}


	if (data->ctl.subtype >= 8) { 
		printf(" 802.11e: QoS = 0x%04x\n", qos->qos);
		if (len > sizeof(ieee80211_qos_data_frame)) 
			hdrlen = sizeof(ieee80211_qos_data_frame);
	}
	
	if (len > hdrlen) {
		int payload_offset = 0;
		uint16_t ethertype = 0;
		pld = (ieee80211_payload *) ((char *)pkt + hdrlen) ;
		if (ntohs(pld->ethertype) == 0xaaaa) {
			/* 802.11 payload contains an 802.2 LLC/SNAP header */
			libtrace_llcsnap_t *llcsnap = (libtrace_llcsnap_t *) pld;
			printf(" 802.2: DSAP = 0x%x, SSAP = 0x%x, OUI = 0x%x, Type = 0x%x\n", 
					llcsnap->dsap, llcsnap->ssap, llcsnap->oui, ntohs(llcsnap->type));
			payload_offset = sizeof(libtrace_llcsnap_t);
			ethertype = ntohs(llcsnap->type);
		} else {
			/* 802.11 payload contains an Ethernet II frame */
			printf(" 802.11MAC: Payload ethertype = 0x%04x\n", ntohs(pld->ethertype));
			payload_offset = sizeof(pld->ethertype);
			ethertype = ntohs(pld->ethertype);
		}
		decode_next((char *) pkt + hdrlen + payload_offset, 
				len - hdrlen - payload_offset, "eth", ethertype);
	}

	
}

DLLEXPORT void decode(int link_type UNUSED, const char *pkt, unsigned len) 
{
	ieee80211_frame_control *fc;
	
	if (len < sizeof(ieee80211_frame_control)) {
		printf(" 802.11MAC: Truncated at frame control field\n");
		return;
	}

	fc = (ieee80211_frame_control *) pkt;	

	printf(" 802.11MAC: ");

	printf("proto = %d, type = %d, subtype = %d, ", fc->version, fc->type, fc->subtype);

	printf("flags =");
	if (fc->to_ds) printf(" toDS");
	if (fc->from_ds) printf(" fromDS");
	if (fc->more_frag) printf(" moreFrag");
	if (fc->retry) printf(" retry");
	if (fc->power) printf(" pwrMgmt");
	if (fc->more_data) printf(" moreData");
	if (fc->wep) printf(" WEP");
	if (fc->order) printf(" order");

	printf("\n");
	switch (fc->type) {
		case 0:
			decode_80211_mgmt(pkt, len);
			break;
		case 1:
			decode_80211_ctrl(pkt, len);
			break;
		case 2:
			decode_80211_data(pkt, len);
			break;
		case 3:
			printf(" Unable to decode frame type %u, dumping rest of packet\n", fc->type);
			decode_next(pkt + sizeof(ieee80211_frame_control), len - sizeof(ieee80211_frame_control), "unknown", 0);
			
			break;
	}

}


