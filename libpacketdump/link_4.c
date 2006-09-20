/* 
 * 802.11 libpacketdump decoder
 * 
 * Based on "wagdump" (c) 2005 Dean Armstrong
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include "libpacketdump.h"
#include "libtrace.h"

/* NB: this struct is just used for length */
struct ieee_802_11_header {
        uint8_t      protocol:2;
        uint8_t      type:2;
        uint8_t      subtype:4;
        uint8_t      to_ds:1;
        uint8_t      from_ds:1;
        uint8_t      more_frag:1;
        uint8_t      retry:1;
        uint8_t      power:1;
        uint8_t      more_data:1;
        uint8_t      wep:1;
        uint8_t      order:1;
        uint16_t     duration;
        uint8_t      mac1[6];
        uint8_t      mac2[6];
        uint8_t      mac3[6];
        uint16_t     SeqCtl;
        uint8_t      mac4[6];
}__attribute__ ((__packed__));

struct ieee_802_11_e_payload {
	uint16_t	qos;
	uint16_t	type;
	uint8_t		data[1];
}__attribute__ ((__packed__));

struct ieee_802_11_payload {
        uint16_t     type;
        uint8_t      data[1];
}__attribute__ ((__packed__));


char *macaddr(uint8_t *mac) {
	static char ether_buf[18] = {0, };
	trace_ether_ntoa(mac, ether_buf);
	return ether_buf;
}

void decode(int link_type, char *pkt, int len) 
{
	int version, type, subtype, flags, duration, seq_ctrl;
	bool is_wme = false;

	if (len == 0) {
		printf("Zero length packet!\n");
		return;
	}

	version = (pkt[0] & 0x3);
	type = (pkt[0] & 0x0c) >> 2;
	subtype = (pkt[0] & 0xf0) >> 4;
	flags = pkt[1];
	seq_ctrl = *(uint16_t *)&pkt[22];

	printf(" 802.11MAC: ");

	printf("proto = %d, type = %d, subtype = %d, ", version, type, subtype);

	printf("flags =");
	if (flags == 0)
		printf(" 0");
	if (flags & 0x01) printf(" toDS");
	if (flags & 0x02) printf(" fromDS");
	if (flags & 0x04) printf(" moreFrag");
	if (flags & 0x08) printf(" retry");
	if (flags & 0x10) printf(" pwrMgmt");
	if (flags & 0x20) printf(" moreData");
	if (flags & 0x40) printf(" WEP");
	if (flags & 0x80) printf(" order");

	if (type == 2)
		printf(", seq_ctrl = %d", seq_ctrl);

	printf("\n 802.11MAC: ");
	switch (type) {
		case 0:
			printf("Management frame: ");
			switch (subtype) {
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
			break;
		case 1:
			printf("Control frame: ");
			switch (subtype) {
				case 8: printf("BlockAckReq"); break;
				case 9: printf("BlockAck"); break;
				case 10: printf("PS-Poll"); break;
				case 11: printf("RTS"); break;
				case 12: printf("CTS"); break;
				case 13: printf("ACK"); break;
				case 14: printf("CF-End"); break;
				case 15: printf("CF-End + CF-Ack"); break;
				default: printf("RESERVED"); break;
			}
			break;
		case 2:
			printf("Data frame: ");
			/* Check to see if the frame has WME QoS bits */
			if (subtype >= 8) is_wme = true;

			switch (subtype) {
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
			break;
		case 3:
			printf("BAD FRAME TYPE!");
			break;
	}

	duration = ((uint32_t)pkt[2] << 8) + pkt[3];
	printf(" (duration = %d)\n", duration);

	switch (type) {
		case 0:
			printf(" 802.11MAC: DA      = %s\n", macaddr(&pkt[4]));
			printf(" 802.11MAC: SA      = %s\n", macaddr(&pkt[10]));
			printf(" 802.11MAC: BSSID   = %s\n", macaddr(&pkt[16]));
			break;
		case 1:
			switch (subtype) {
				case 11:
					printf(" 802.11MAC: SA      = %s\n", macaddr(&pkt[10]));
				case 12:
				case 13:
					printf(" 802.11MAC: RA      = %s\n", macaddr(&pkt[4]));
					break;
			}
		case 2: // Data packet
			if (subtype == 0 || subtype == 8) {
					switch (pkt[1] & 0x3) {
						case 0x0:
							printf(" 802.11MAC: DA      = %s\n", macaddr(&pkt[4]));
							printf(" 802.11MAC: SA      = %s\n", macaddr(&pkt[10]));
							printf(" 802.11MAC: BSSID   = %s\n", macaddr(&pkt[16]));
							break;
						case 0x1: // To DS
							printf(" 802.11MAC: DA      = %s\n", macaddr(&pkt[16]));
							printf(" 802.11MAC: SA      = %s\n", macaddr(&pkt[10]));
							printf(" 802.11MAC: BSSID   = %s\n", macaddr(&pkt[4]));
							break;
						case 0x2: // From DS
							printf(" 802.11MAC: DA      = %s\n", macaddr(&pkt[4]));
							printf(" 802.11MAC: SA      = %s\n", macaddr(&pkt[16]));
							printf(" 802.11MAC: BSSID   = %s\n", macaddr(&pkt[10]));
							break;
						case 0x3: // To DS + From DS
							printf(" 802.11MAC: DA      = %s\n", macaddr(&pkt[16]));
							printf(" 802.11MAC: SA      = %s\n", macaddr(&pkt[24]));
							printf(" 802.11MAC: TA      = %s\n", macaddr(&pkt[10]));
							printf(" 802.11MAC: RA      = %s\n", macaddr(&pkt[4]));
							break;
					}
			}
			break;
	}

	char *data;
	int extra = 0;	
	uint16_t ethtype = 0;
	if (is_wme) {
		struct ieee_802_11_e_payload *pld = (struct ieee_802_11_e_payload *) ((char*)pkt + sizeof(struct ieee_802_11_header));
		
		printf(" 802.11e: QoS = 0x%04x\n", pld->qos);
	
		ethtype = htons(pld->type);
		data = (char *) pld->data;
		extra = 2;
	} else {
		struct ieee_802_11_payload *pld = (struct ieee_802_11_payload *) ((char *)pkt + sizeof(struct ieee_802_11_header));
		ethtype = htons(pld->type);
		data = (char *) pld->data;
	}
	
	printf(" 802.11MAC: Payload Type = %04x\n",ethtype);
	decode_next(data,len-(sizeof(struct ieee_802_11_header))-extra,"eth",ethtype);
	

}


