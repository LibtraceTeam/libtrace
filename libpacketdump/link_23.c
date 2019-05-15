/** PCAPNG META PACKET */
#include "libtrace.h"
#include "libtrace_int.h"
#include "libpacketdump.h"
#include "format_pcapng.h"
#include "byteswap.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <inttypes.h>

DLLEXPORT void decode(int link_type UNUSED,const char *packet UNUSED,unsigned len UNUSED) {
};

static void print_section_type(libtrace_meta_t *r) {
	int i;
	printf(" PCAPNG Section Header Block\n");

	if (r == NULL) { return; }

        for (i=0; i<r->num; i++) {
        	switch(r->items[i].option) {
                	case(PCAPNG_META_SHB_HARDWARE):
                        	printf("  shb_hardware: %s\n",
                                	(char *)r->items[i].data);
                                break;
                        case(PCAPNG_META_SHB_OS):
                                printf("  shb_os: %s\n",
                                        (char *)r->items[i].data);
                                break;
                        case(PCAPNG_META_SHB_USERAPPL):
                                printf("  shb_userappl: %s\n",
                                        (char *)r->items[i].data);
                                break;
        	}
	}
}
static void print_interface_type(libtrace_meta_t *r, libtrace_packet_t *packet) {
	int i;
	struct in_addr ip;
	unsigned char *tmp;
	char *ip6, *ptr UNUSED;
	printf(" PCAPNG Interface Description Block\n");

	if (r == NULL) { return; }

	for (i=0; i<r->num; i++) {
		switch(r->items[i].option) {
			case(PCAPNG_META_IF_NAME):
				printf("  if_name: %s\n",
					(char *)r->items[i].data);
				break;
			case(PCAPNG_META_IF_DESCR):
				printf("  if_description: %s\n",
					(char *)r->items[i].data);
				break;
			case(PCAPNG_META_IF_IP4):
				ip.s_addr = *(uint32_t *)r->items[i].data;
				printf("  if_IPv4addr: %s", inet_ntoa(ip));
				break;
			case(PCAPNG_META_IF_IP6):
				ip6 = calloc(1, INET6_ADDRSTRLEN);
				ptr = trace_get_interface_ipv6_string(packet, ip6,
					INET6_ADDRSTRLEN, 0);
				printf("  if_IPv6addr: %s\n", ip6);
				free(ip6);
				break;
			case(PCAPNG_META_IF_MAC):
				tmp = r->items[i].data;
				printf("  if_MACaddr: %02x:%02x:%02x:%02x:%02x:%02x\n",
					tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]);
				break;
			case(PCAPNG_META_IF_EUI):
				tmp = r->items[i].data;
				printf("  if_EUIaddr: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
					tmp[0], tmp[1], tmp[2], tmp[3],
					tmp[4], tmp[5], tmp[6], tmp[7]);
				break;
			case(PCAPNG_META_IF_SPEED):
				printf("  if_speed: %" PRIu64 "\n",
					*(uint64_t *)r->items[i].data);
				break;
			case(PCAPNG_META_IF_TSRESOL):
				printf("  if_tsresol: %" PRIu8 "\n",
					*(uint8_t *)r->items[i].data);
				break;
			case(PCAPNG_META_IF_TZONE):
				/* Waiting for specification to specify */
				break;
			case(PCAPNG_META_IF_FILTER):
				printf("  if_filter: %" PRIu8 "",
					*(uint8_t *)r->items[i].data);
				printf(" %s\n",
					(char *)r->items[i].data+sizeof(uint8_t));
				break;
			case(PCAPNG_META_IF_OS):
				printf("  if_os: %s\n",
					(char *)r->items[i].data);
				break;
			case(PCAPNG_META_IF_FCSLEN):
				printf("  if_fcslen: %" PRIu8 "\n",
					*(uint8_t *)r->items[i].data);
				break;
			case(PCAPNG_META_IF_TSOFFSET):
				printf("  if_tsoffset: %" PRIu64 "\n",
					*(uint64_t *)r->items[i].data);
				break;
			case(PCAPNG_META_IF_HARDWARE):
				printf("  if_hardware: %s\n",
					(char *)r->items[i].data);
				break;
			default:
				break;
		}
	}
}

static void print_name_resolution_type(libtrace_meta_t *r) {
	int i;
	struct in_addr ip;
	printf(" PCAPNG Name Resolution\n");
	if (r == NULL) { return; }

	for (i=0; i<r->num; i++) {
		switch(r->items[i].option) {
			case(PCAPNG_META_NRB_RECORD_IP4):
				ip.s_addr = *(uint32_t *)r->items[i].data;
				printf("  nrb_record_ipv4: %s dns_name: %s\n",
					inet_ntoa(ip),
					(char *)(r->items[i].data+sizeof(uint32_t)));
				break;
			case(PCAPNG_META_NRB_RECORD_IP6):
				/* todo - need to find an example */
				break;
			//case(PCAPNG_META_NS_DNSNAME):
			//	printf("  ns_dnsname: %s\n",
			//		(char *)r->items[i].data);
			//	break;
			//case(PCAPNG_META_NS_DNS_IP4_ADDR):
			//	printf("  ns_dnsIP4addr: %u.%u.%u.%u\n",
			//		*(uint8_t *)r->items[i].data,
			//		*(uint8_t *)r->items[i].data+8,
			//		*(uint8_t *)r->items[i].data+16,
			//		*(uint8_t *)r->items[i].data+24);
			//	break;
			//case(PCAPNG_META_NS_DNS_IP6_ADDR):
			//	/* todo - need to find an example */
			//	break;
			default:
				break;
		}
	}
}

static void print_interface_statistics_type(libtrace_meta_t *r) {
	int i;
        printf(" PCAPNG Interface Statistics\n");

	if (r == NULL) { return; }

        for (i=0; i<r->num; i++) {
                switch(r->items[i].option) {
			case(PCAPNG_META_ISB_STARTTIME):
				/* Need to split into 4 octets */
				printf("  isb_starttime: %" PRIu64 "\n",
                                        *(uint64_t *)r->items[i].data);
                                break;
			case(PCAPNG_META_ISB_ENDTIME):
				printf("  isb_endtime: %" PRIu64 "\n",
					*(uint64_t *)r->items[i].data);
				break;
			case(PCAPNG_META_ISB_IFRECV):
				printf("  isb_ifrecv: %" PRIu64 "\n",
                                        *(uint64_t *)r->items[i].data);
                                break;
			case(PCAPNG_META_ISB_IFDROP):
				printf("  isb_ifdrop: %" PRIu64 "\n",
                                        *(uint64_t *)r->items[i].data);
                                break;
			case(PCAPNG_META_ISB_FILTERACCEPT):
				printf("  isb_filteraccept: %" PRIu64 "\n",
                                        *(uint64_t *)r->items[i].data);
                                break;
			case(PCAPNG_META_ISB_OSDROP):
				printf("  isb_osdrop: %" PRIu64 "\n",
                                        *(uint64_t *)r->items[i].data);
                                break;
			case(PCAPNG_META_ISB_USRDELIV):
				printf("  isb_usrdeliv: %" PRIu64 "\n",
                                        *(uint64_t *)r->items[i].data);
                                break;
			default:
				break;
		}
	}
}

static void print_custom_type(libtrace_meta_t *r) {
	int i, k;
	printf(" PCAPNG Custom Block\n");

	if (r == NULL) { return; }

	/* print the custom data */
	for (i=0; i<r->num; i++) {
		printf("  Private Enterprise Number (PEN): %" PRIu32 "\n",
			*(uint32_t *)r->items[i].data);
		printf("   Data: ");
		char *ptr = r->items[i].data+sizeof(uint32_t);
		uint16_t length = r->items[i].len-sizeof(uint32_t);
		for (k=0; k<length; k++) {
			printf("%02x ", ptr[k]);
		}
	}
}

static void print_secrets_type(libtrace_meta_t *r UNUSED) {
	/* todo */
}

DLLEXPORT void decode_meta(int link_type UNUSED,const char *packet UNUSED,unsigned len UNUSED,
	libtrace_packet_t *p) {

	struct pcapng_peeker *pkthdr;
	uint32_t section;

	/* get the section header ID */
	pkthdr = (struct pcapng_peeker *)p->header;
	if (DATA(p->trace)->byteswapped) {
		section = byteswap32(pkthdr->blocktype);
	} else {
		section = pkthdr->blocktype;
	}

	/* Get the entire section of whatever type of meta packet this is from the meta api */
        libtrace_meta_t *r = trace_get_all_metadata(p);

	switch(section) {
		case PCAPNG_SECTION_TYPE:
			print_section_type(r);
			break;
		case PCAPNG_INTERFACE_TYPE:
			print_interface_type(r, p);
			break;
		case PCAPNG_OLD_PACKET_TYPE:
			/* We will never make it here */
			break;
		case PCAPNG_SIMPLE_PACKET_TYPE:
			/* We will never make it here */
			break;
		case PCAPNG_NAME_RESOLUTION_TYPE:
			print_name_resolution_type(r);
			break;
		case PCAPNG_INTERFACE_STATS_TYPE:
			print_interface_statistics_type(r);
			break;
		case PCAPNG_ENHANCED_PACKET_TYPE:
			/* We will never make it here */
			break;
		case PCAPNG_CUSTOM_TYPE:
			print_custom_type(r);
			break;
		case PCAPNG_CUSTOM_NONCOPY_TYPE:
			print_custom_type(r);
			break;
		case PCAPNG_DECRYPTION_SECRETS_TYPE:
			/* specification does not define options for this
			 * however we can still print the secrets data */
			print_secrets_type(r);
			break;
		default:
			printf("Unknown Type/Block\n");

	}

	/* destroy the meta result */
	trace_destroy_meta(r);

}
