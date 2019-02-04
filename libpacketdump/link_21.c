/* ERF META PACKET */
#include "libtrace.h"
#include "libpacketdump.h"
#include "format_erf.h"

#include <arpa/inet.h>

DLLEXPORT void decode(int link_type UNUSED, const char *packet UNUSED, unsigned len UNUSED) {
}

static void print_section(libtrace_meta_t *meta) {
	int i;
	for (i=0; i<meta->num; i++) {

		if (meta->items[i].datatype == TRACE_META_STRING) {
			printf("   %s: %s\n",
				meta->items[i].option_name,
				(char *)meta->items[i].data);
		} else if (meta->items[i].datatype == TRACE_META_UINT8) {
			printf("   %s: %u\n",
                                meta->items[i].option_name,
				*(uint8_t *)meta->items[i].data);
		} else if (meta->items[i].datatype == TRACE_META_UINT32) {
			printf("   %s: %u\n",
                                meta->items[i].option_name,
				*(uint32_t *)meta->items[i].data);
		} else if (meta->items[i].datatype == TRACE_META_UINT64) {
			printf("   %s: %lu\n",
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
			printf("   Unknown Option ID %u (output RAW): ", meta->items[i].option);
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

	/* Try to find each section from the meta packet */
	libtrace_meta_t *sec_cap = trace_get_section(p, ERF_PROV_SECTION_CAPTURE);
	libtrace_meta_t *sec_host = trace_get_section(p, ERF_PROV_SECTION_HOST);
	libtrace_meta_t *sec_module = trace_get_section(p, ERF_PROV_SECTION_MODULE);
	libtrace_meta_t *sec_interface = trace_get_section(p, ERF_PROV_SECTION_INTERFACE);

	if (sec_cap != NULL) {
		printf("  Capture Section\n");
		print_section(sec_cap);
		trace_destroy_meta(sec_cap);
	}

	if (sec_host != NULL) {
		printf("  Host Section\n");
		print_section(sec_host);
		trace_destroy_meta(sec_host);
	}

	if (sec_module != NULL) {
		printf("  Module Section\n");
		print_section(sec_module);
		trace_destroy_meta(sec_module);
	}

	if (sec_interface != NULL) {
		printf("  Interface Section\n");
		print_section(sec_interface);
		trace_destroy_meta(sec_interface);
	}

}
