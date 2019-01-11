#include "libtrace_int.h"
#include "libtrace.h"
#include "format_erf.h"
#include "format_pcapng.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* API functions to retrieve interface related packet data */



/* Reads the interface name for a packet
 *
 * @params libtrace_packet_t packet
 * @returns pointer to NULL terminated string containing the interface name
 */

char *trace_get_interface_name(libtrace_packet_t *packet) {
	void *ptr = NULL;

	/* find the result if we havnt already */
	if (packet->meta.interface_name != NULL) {
		return packet->meta.interface_name;
	}

	/* get the result */
	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		ptr = packet->trace->format->get_meta_data(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_NAME);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		ptr = packet->trace->format->get_meta_data(packet,
			PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_NAME);
	}

	/* If a result was found */
	if (ptr != NULL) {
		libtrace_meta_result_t *result = (libtrace_meta_result_t *)ptr;

		/* store this result against the packet itself */
		packet->meta.interface_name = malloc(ntohs(result->len)+1);
		/* add NULL terminator to string */
		packet->meta.interface_name[ntohs(result->len)] = '\0';
		/* copy result over */
		memcpy(packet->meta.interface_name, ptr+sizeof(libtrace_meta_result_t),
			ntohs(result->len));

		return packet->meta.interface_name;
	}

	return NULL;
}

/* Gets the interface MAC address from a meta packet
 *
 * @params libtrace_packet_t packet
 * @returns A pointer to a MAC address
 */
char *trace_get_interface_mac(libtrace_packet_t *packet) {
	void *ptr = NULL;

	if (packet->meta.interface_mac != NULL) {
		return packet->meta.interface_mac;
	}

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		ptr = packet->trace->format->get_meta_data(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_MAC);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		ptr = packet->trace->format->get_meta_data(packet,
			PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_MAC);
	}

	if (ptr != NULL) {
		/* allocate memory within the packet to store the result
		 * exclude any padding that could be included */
		packet->meta.interface_mac = malloc(6);
		/* copy result over */
		memcpy(packet->meta.interface_mac, ptr+sizeof(libtrace_meta_result_t), 6);

		return packet->meta.interface_mac;
	}

	return NULL;
}

/* Gets the interface speed from a meta packet
 *
 * @params libtrace_packet_t packet
 * @returns uint64_t containing the interface speed or 0 if not found.
 */
uint64_t trace_get_interface_speed(libtrace_packet_t *packet) {
	/* Get the result */
	void *ptr = packet->trace->format->get_meta_data(packet,
                ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_SPEED);

	/* If a result was found */
	if (ptr != NULL) {
		uint64_t *result = (uint64_t *)(ptr+sizeof(libtrace_meta_result_t));
		packet->meta.interface_speed = *result;

		return packet->meta.interface_speed;
	}

	return 0;
}

/* Gets the interface ipv4 address from a meta packet
 *
 * @params libtrace_packet_t packet
 * @returns A pointer to the IP4 address field within the packet
 */
uint32_t trace_get_interface_ip4(libtrace_packet_t *packet) {
	void *ptr = packet->trace->format->get_meta_data(packet,
		ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_IPV4);

	if (ptr != NULL) {
		uint32_t *result = (uint32_t *)(ptr+sizeof(libtrace_meta_result_t));
		packet->meta.interface_ipv4 = *result;

		return packet->meta.interface_ipv4;
	}

	return 0;
}
uint32_t trace_get_interface_ipv4(libtrace_packet_t *packet) {
	return trace_get_interface_ip4(packet);
}

char *trace_get_interface_ip6(libtrace_packet_t *packet UNUSED) {
	return NULL;
}
char *trace_get_interface_ipv6(libtrace_packet_t *packet) {
	return trace_get_interface_ip6(packet);
}

/* Gets the interface description for a packet
 *
 * @params libtrace_packet_t packet
 * @returns A char* to a NULL terminated interface description
 */
char *trace_get_interface_description(libtrace_packet_t *packet) {
	if (packet->meta.interface_description != NULL) {
		return packet->meta.interface_description;
	}

	void *ptr = packet->trace->format->get_meta_data(packet,
		ERF_PROV_SECTION_INTERFACE, ERF_PROV_DESCR);

	if (ptr != NULL) {
		libtrace_meta_result_t *result = (libtrace_meta_result_t *)ptr;
		packet->meta.interface_description = malloc(ntohs(result->len)+1);
		packet->meta.interface_description[ntohs(result->len)] = '\0';
		memcpy(packet->meta.interface_description, ptr+sizeof(libtrace_meta_result_t),
			ntohs(result->len));

		return packet->meta.interface_description;
	}

	return NULL;
}

libtrace_meta_result_t *trace_get_interface_num(libtrace_packet_t *packet) {
	libtrace_meta_result_t *result = packet->trace->format->get_meta_data(packet,
		ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_NUM);
	return result;
}

libtrace_meta_result_t *trace_get_host_os(libtrace_packet_t *packet UNUSED) {
	return NULL;
}

libtrace_meta_result_t *trace_get_tzone(libtrace_packet_t *packet UNUSED) {
	return NULL;
}

libtrace_meta_result_t *trace_get_app_name(libtrace_packet_t *packet UNUSED) {
	return NULL;
}
