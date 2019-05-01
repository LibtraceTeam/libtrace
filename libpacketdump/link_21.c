/* ERF META PACKET */
#include "libtrace.h"
#include "libpacketdump.h"
#include "format_erf.h"

#include <arpa/inet.h>
#include <inttypes.h>

DLLEXPORT void decode(int link_type UNUSED, const char *packet UNUSED, unsigned len UNUSED) {
}

static void print_meta_contents(libtrace_meta_t *meta) {
	int i;
        uint16_t last_sec = 0;

	for (i=0; i<meta->num; i++) {
                if (meta->items[i].section != last_sec) {
                        switch(meta->items[i].section) {
                                case ERF_PROV_SECTION_CAPTURE:
                                        printf("  Capture section:\n");
                                        break;
                                case ERF_PROV_SECTION_HOST:
                                        printf("  Host section:\n");
                                        break;
                                case ERF_PROV_SECTION_MODULE:
                                        printf("  Module section:\n");
                                        break;
                                case ERF_PROV_SECTION_INTERFACE:
                                        printf("  Interface section:\n");
                                        break;
                                case ERF_PROV_SECTION_STREAM:
                                        printf("  Stream section:\n");
                                        break;
                        }
                        last_sec = meta->items[i].section;
                }

                if (meta->items[i].option == ERF_PROV_GEN_TIME) {
                        continue;
                }

		if (meta->items[i].datatype == TRACE_META_STRING) {
			printf("   %s: %s\n",
				meta->items[i].option_name,
				(char *)meta->items[i].data);
		} else if (meta->items[i].datatype == TRACE_META_UINT8) {
			printf("   %s: %" PRIu8 "\n",
                                meta->items[i].option_name,
				*(uint8_t *)meta->items[i].data);
		} else if (meta->items[i].datatype == TRACE_META_UINT32) {
			printf("   %s: %" PRIu32 "\n",
                                meta->items[i].option_name,
				*(uint32_t *)meta->items[i].data);
		} else if (meta->items[i].datatype == TRACE_META_UINT64) {
			printf("   %s: %" PRIu64 "\n",
                                meta->items[i].option_name,
				*(uint64_t *)meta->items[i].data);
		} else if (meta->items[i].datatype == TRACE_META_IPV4) {
			struct in_addr ip;
			ip.s_addr = *(uint32_t *)meta->items[i].data;
			printf("   %s: %s\n",
				meta->items[i].option_name,
				inet_ntoa(ip));
		} else if (meta->items[i].datatype == TRACE_META_IPV6) {
			printf("   %s: %s\n",
                                meta->items[i].option_name,
				(char *)meta->items[i].data);
		} else if (meta->items[i].datatype == TRACE_META_MAC) {
			unsigned char *mac = meta->items[i].data;
			printf("   %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
				meta->items[i].option_name,
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		} else {
			printf("   Unknown Option ID %" PRIu16 " (output RAW): ", meta->items[i].option);
			int k;
			unsigned char *curr = (unsigned char *)meta->items[i].data;
			for (k=0; k<meta->items[i].len; k++) {
				printf("%02x ", curr[k]);
			}
			printf("\n");
		}
	}
}

DLLEXPORT void decode_meta(int link_type UNUSED, const char *packet UNUSED, unsigned len UNUSED,
	libtrace_packet_t *p) {

	printf(" ERF Provenance Packet\n");
	libtrace_meta_t *sec_all = trace_get_all_metadata(p);

	if (sec_all != NULL) {
		print_meta_contents(sec_all);
		trace_destroy_meta(sec_all);
	}
}
