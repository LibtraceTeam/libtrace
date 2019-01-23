/* ERF META PACKET */
#include "libtrace.h"
#include "libpacketdump.h"
#include "format_erf.h"

DLLEXPORT void decode(int link_type UNUSED, const char *packet UNUSED, unsigned len UNUSED) {
}

static void print_section(libtrace_meta_t *meta) {
	int i;
	for (i=0; i<meta->num; i++) {
		printf("   Option ID: %u Option Value: %s\n",
			meta->items[i].option, (char *)meta->items[i].data);
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
