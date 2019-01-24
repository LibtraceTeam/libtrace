/* ERF META PACKET */
#include "libtrace.h"
#include "libpacketdump.h"
#include "format_erf.h"

#include <arpa/inet.h>
#include <netinet/ether.h>

DLLEXPORT void decode(int link_type UNUSED, const char *packet UNUSED, unsigned len UNUSED) {
}

static void print_section(libtrace_meta_t *meta) {
	int i;
	for (i=0; i<meta->num; i++) {

		if (meta->items[i].datatype == TRACE_META_STRING) {
			printf("   Name: %s ID: %u Value: %s\n",
				meta->items[i].option_name,
				meta->items[i].option,
				(char *)meta->items[i].data);
		} else if (meta->items[i].datatype == TRACE_META_UINT8) {
			printf("   Name: %s ID: %u Value: %u\n",
                                meta->items[i].option_name,
				meta->items[i].option,
				*(uint8_t *)meta->items[i].data);
		} else if (meta->items[i].datatype == TRACE_META_UINT32) {
			printf("   Name: %s ID: %u Value: %u\n",
                                meta->items[i].option_name,
				meta->items[i].option,
				*(uint32_t *)meta->items[i].data);
		} else if (meta->items[i].datatype == TRACE_META_UINT64) {
			printf("   Name: %s ID: %u Value: %lu\n",
                                meta->items[i].option_name,
				meta->items[i].option,
				*(uint64_t *)meta->items[i].data);
		} else if (meta->items[i].datatype == TRACE_META_IPV4) {
			struct in_addr ip;
			ip.s_addr = *(uint32_t *)meta->items[i].data;
			printf("   Name: %s ID: %u Value: %s\n",
				meta->items[i].option_name,
				meta->items[i].option,
				inet_ntoa(ip));
		} else if (meta->items[i].datatype == TRACE_META_IPV6) {
			printf("   Name: %s ID: %u Value: %s\n",
                                meta->items[i].option_name,
				meta->items[i].option,
				(char *)meta->items[i].data);
		} else if (meta->items[i].datatype == TRACE_META_MAC) {
			printf("   Name: %s ID: %u Value: %s\n",
				meta->items[i].option_name,
                                meta->items[i].option,
				ether_ntoa((struct ether_addr *)(char *)meta->items[i].data));
		} else {
			printf("   Option ID: %u Option Value: ", meta->items[i].option);
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
