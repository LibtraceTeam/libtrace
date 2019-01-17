#include "libtrace_int.h"
#include "libtrace.h"
#include "format_erf.h"
#include "format_pcapng.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* Internal Meta functions */
static int trace_meta_check_input(libtrace_packet_t *packet, char *input_func) {
	if (packet == NULL) {
                fprintf(stderr, "NULL packet passed into %s\n", input_func);
                return -1;
        }
        if (packet->trace == NULL) {
                fprintf(stderr, "Packet contains NULL trace in %s\n", input_func);
                return -1;
        }
	return 1;
}

/* API functions to retrieve interface related packet data */

/* Destroy libtrace_meta_t structure
 *
 * @params libtrace_meta_t structure
 * returns 1 on success, -1 on failure
 */
int trace_destroy_meta(libtrace_meta_t *result) {
        int i;
        if (!result) { return -1; }

	for (i=0;i<result->num;i++) {
		if(result->items[i].data) {
			free(result->items[i].data);
		}
	}
        if (result->items) {
		free(result->items);
	}
	if (result) {
        	free(result);
	}

        return 1;
}

/* Get the interface name/s for a meta packet.
 * Must be destroyed with trace_destroy_meta().
 *
 * @params libtrace_packet_t meta packet.
 * @returns Pointer to libtrace_meta_t structure containing all found interface names
 * or NULL.
 */
libtrace_meta_t *trace_get_interface_name_meta(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_name()")<0) {
		return NULL;
	}

	/* get the result */
	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_option(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_NAME);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_option(packet,
			PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_NAME);
	}

	return NULL;
}
/* Get the interface name for a meta packet.
 * Note: ERF packets can contain multiple interfaces per meta packet. Use index to
 * specify the interface index.
 *
 * @params libtrace_packet_t meta packet to extract the interface name from.
 * @params A pointer to a character buffer to store the interface name in.
 * @params The size of the buffer passed in.
 * @params The interface index within the meta packet.
 * @returns Pointer to the character buffer containing the interface name or NULL.
 */
char *trace_get_interface_name(libtrace_packet_t *packet, char *space, int spacelen,
	int index) {

	libtrace_meta_t *r = trace_get_interface_name_meta(packet);
	if (r == NULL) { return NULL; }
	/* If there is not a result for the index return */
	if (r->num <= index) { return NULL; }
	/* Ensure the supplied memory allocation is enough, if not only fill
	 * what we can */
	if (spacelen > r->items[index].len) {
		memcpy(space, r->items[index].data, r->items[index].len);
	} else {
		memcpy(space, r->items[index].data, spacelen);
	}
	trace_destroy_meta(r);
	return space;
}
/* Get the interface MAC address/s for a meta packet.
 * Must be destroyed with trace_destroy_meta().
 *
 * @params libtrace_packet_t meta packet.
 * @returns Pointer to libtrace_meta_t structure containing all found interface mac
 * addresses or NULL.
 */
libtrace_meta_t *trace_get_interface_mac_meta(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_mac()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_option(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_MAC);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_option(packet,
			PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_MAC);
	}

	return NULL;
}
/* Get the interface MAC address for a meta packet.
 * Note: ERF packets can contain multiple interfaces per meta packet. Use index to
 * specify the interface index.
 *
 * @params libtrace_packet_t meta packet to extract the MAC address from.
 * @params A pointer to a character buffer to store the MAC address in.
 * @params The size of the buffer passed in.
 * @params The interface index within the meta packet.
 * @returns Pointer to the character buffer containing the MAC address or NULL.
 */
char *trace_get_interface_mac(libtrace_packet_t *packet, char *space, int spacelen,
	int index) {

	libtrace_meta_t *r = trace_get_interface_mac_meta(packet);
	if (r == NULL) { return NULL; }
	if (index >= r->num) { return NULL; }
	if (r->items[index].len > spacelen) {
		memcpy(space, r->items[index].data, spacelen);
	} else {
		memcpy(space, r->items[index].data, r->items[index].len);
	}
	trace_destroy_meta(r);
	return space;
}

/* Get the interface speed/s from a meta packet.
 * Must be destroyed with trace_destroy_meta().
 *
 * @params libtrace_packet_t packet.
 * @returns Pointer to libtrace_meta_t structure containing all found interface
 * speeds or NULL.
 */
libtrace_meta_t *trace_get_interface_speed_meta(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_speed()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_option(packet,
                	ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_SPEED);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_option(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_SPEED);
	}

	return NULL;
}
/* Get the interface speed for a meta packet.
 * Note: ERF packets can contain multiple interfaces per meta packet. Use index to
 * specify the interface index.
 *
 * @params libtrace_packet_t meta packet to extract the interface speed from.
 * @params The interface index within the meta packet.
 * @returns uint64_t interface speed or NULL.
 */
uint64_t trace_get_interface_speed(libtrace_packet_t *packet, int index) {
	libtrace_meta_t *r = trace_get_interface_speed_meta(packet);
	if (r == NULL) { return 0; }
	/* If the index wanted does not exist return 0 */
	if (index >= r->num) { return 0; }
	/* Need to check this more ERF reports this in network order */
	uint64_t data = *(uint64_t *)r->items[index].data;
	trace_destroy_meta(r);
	return data;
}

/* Get the interface ipv4 address/s for a meta packet.
 * Must be destroyed with trace_destroy_meta().
 *
 * @params libtrace_packet_t meta packet.
 * @returns Pointer to libtrace_meta_t structure containing all found ipv4 addresses
 * or NULL
 */
libtrace_meta_t *trace_get_interface_ipv4_meta(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_ip4()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_option(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_IPV4);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_option(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_IP4);
	}

	return NULL;
}
/* Get the interface ipv4 address for a meta packet.
 * Note: ERF packets can contain multiple interfaces per meta packet. Use index to
 * specify the interface index.
 *
 * @params libtrace_packet_t meta packet to extract the ipv4 address from.
 * @params The interface index within the meta packet.
 * @returns uint32_t ipv4 address or 0.
 */
uint32_t trace_get_interface_ipv4(libtrace_packet_t *packet, int index) {
	libtrace_meta_t *r = trace_get_interface_ipv4_meta(packet);
	if (r == NULL) { return 0; }
	if (index >= r->num) { return 0; }
	uint32_t data = *(uint32_t *)r->items[index].data;
	trace_destroy_meta(r);
	return data;
}
/* Get the interface ipv4 address string for a meta packet.
 * Note: ERF packets can contain multiple interfaces per meta packet. Use index to
 * specify the interface index.
 *
 * @params libtrace_packet_t meta packet to extract the ipv4 address from.
 * @params A pointer to a character buffer to store the ipv4 address string in.
 * @params The size of the buffer passed in.
 * @params The interface index within the meta packet.
 * @returns Pointer to the character buffer containing the ipv4 address string or NULL.
 */
char *trace_get_interface_ipv4_string(libtrace_packet_t *packet, char *space, int spacelen,
	int index) {

	uint32_t addr = htonl(trace_get_interface_ipv4(packet, index));
	if (addr == 0) { return NULL; }

	char *addrstr = inet_ntoa(*(struct in_addr *)&addr);
	memcpy(space, addrstr, strlen(addrstr));
	return space;
}

/* Get the interface ipv6 address/s for a meta packet.
 * Must be destroyed with trace_destroy_meta().
 *
 * @params libtrace_packet_t meta packet.
 * @returns Pointer to libtrace_meta_t structure containing all found ipv6 addresses
 * or NULL.
 */
libtrace_meta_t *trace_get_interface_ipv6_meta(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_ip6()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
                return packet->trace->format->get_meta_section_option(packet,
                        ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_IPV4);
        }
        if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
                return packet->trace->format->get_meta_section_option(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_IP4);
        }

	return NULL;
}
/* Get the interface ipv6 address for a meta packet.
 * Note: ERF packets can contain multiple interfaces per meta packet. Use index to
 * specify the interface index.
 *
 * @params libtrace_packet_t meta packet to extract the ipv6 address from.
 * @params A pointer to a character buffer to store the ipv6 address in.
 * @params The size of the buffer passed in.
 * @params The interface index within the meta packet.
 * @returns Pointer to the buffer containing the ipv6 address or NULL.
 */
void *trace_get_interface_ipv6(libtrace_packet_t *packet, void *space, int spacelen,
	int index) {

	libtrace_meta_t *r = trace_get_interface_ipv6_meta(packet);
	if (r == NULL) { return NULL; }
	if (r->num <= index) { return NULL; }
	if (r->items[index].len > spacelen) {
		memcpy(space, r->items[index].data, spacelen);
	} else {
		memcpy(space, r->items[index].data, r->items[index].len);
	}
	trace_destroy_meta(r);
	return space;
}
/* Get the interface ipv6 address string for a meta packet.
 * Note: ERF packets can contain multiple interfaces per meta packet. Use index to
 * specify the interface index.
 *
 * @params libtrace_packet_t meta packet to extract the ipv6 address from.
 * @params A pointer to a character buffer to store the ipv6 address in.
 * @params The size of the buffer passed in.
 * @params The interface index within the meta packet.
 * @returns Pointer to the character buffer containing the ipv6 address string or NULL.
 */
char *trace_get_interface_ipv6_string(libtrace_packet_t *packet, char *space, int spacelen,
	int index) {

	return NULL;
}


/* Get the interface description/s for a meta packet.
 * Must be destroyed with trace_destroy_meta().
 *
 * @params libtrace_packet_t meta packet.
 * @returns Pointer to libtrace_meta_t structure containing all found interface
 * descriptions or NULL.
 */
libtrace_meta_t *trace_get_interface_description_meta(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_description()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_option(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_DESCR);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_option(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_DESCR);
	}

	return NULL;
}
/* Get the interface description for a meta packet.
 * Note: ERF packets can contain multiple interfaces per meta packet. Use index to
 * specify the interface index.
 *
 * @params libtrace_packet_t meta packet to extract the interface description from.
 * @params A pointer to a character buffer to store the interface description in.
 * @params The size of the buffer passed in.
 * @params The interface index within the meta packet.
 * @returns Pointer to the character buffer containing the interface description or NULL.
 */
char *trace_get_interface_description(libtrace_packet_t *packet, char *space, int spacelen,
	int index) {

	libtrace_meta_t *r = trace_get_interface_description_meta(packet);
	if (r == NULL) { return NULL; }
	if (r->num <= index) { return NULL; }
	if (r->items[index].len > spacelen) {
		memcpy(space, r->items[index].data, spacelen);
	} else {
		memcpy(space, r->items[index].data, r->items[index].len);
	}
	trace_destroy_meta(r);
	return space;
}


/* Get the host OS for a meta packet.
 * Must be destroyed with trace_destroy_meta().
 *
 * @params libtrace_packet_t meta packet.
 * @returns Pointer to libtrace_meta_t structure containing the host OS or NULL.
 */
libtrace_meta_t *trace_get_host_os_meta(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_host_os()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_option(packet,
                        ERF_PROV_SECTION_HOST, ERF_PROV_OS);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_option(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_OS);
	}

	return NULL;
}
/* Get the host OS for a meta packet.
 *
 * @params libtrace_packet_t meta packet to extract the host OS from.
 * @params A pointer to a character buffer to store the host OS in.
 * @params The size of the buffer passed in.
 * @returns Pointer to the character buffer containing the host OS or NULL.
 */
char *trace_get_host_os(libtrace_packet_t *packet, char *space, int spacelen) {
	libtrace_meta_t *r = trace_get_host_os_meta(packet);
	if (r == NULL) { return NULL; }
	if (r->items[0].len > spacelen) {
		memcpy(space, r->items[0].data, spacelen);
	} else {
		memcpy(space, r->items[0].data, r->items[0].len);
	}
	trace_destroy_meta(r);
	return space;
}

/* Get the interface frame check sequence length for a meta packet.
 * Must be destroyed with trace_destroy_meta().
 *
 * @params libtrace_packet_t meta packet.
 * @returns Pointer to libtrace_meta_t structure containing all found frame check
 * sequence lengths or NULL.
 */
libtrace_meta_t *trace_get_interface_fcslen_meta(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_frame_check_sequence_length()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_option(packet,
                        ERF_PROV_SECTION_INTERFACE, ERF_PROV_FCS_LEN);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_option(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_FCSLEN);
	}

	return NULL;
}
/* Get the interface frame check sequence length for a meta packet.
 * Note: ERF packets can contain multiple interfaces per meta packet. Use index to
 * specify the interface index.
 *
 * @params libtrace_packet_t meta packet to extract the interface fcslen from.
 * @params The interface index within the meta packet.
 * @returns uint32_t frame check sequence length or 0.
 */
uint32_t trace_get_interface_fcslen(libtrace_packet_t *packet, int index) {
	libtrace_meta_t *r = trace_get_interface_fcslen_meta(packet);
	if (r == NULL) { return 0; }
	if (r->num <= index) { return 0; }
	uint32_t data = *(uint32_t *)r->items[index].data;
	trace_destroy_meta(r);
	return data;
}

/* Get the hardware description
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t meta packet
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_interface_hardware_description_meta(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_hardware_description()")<0) {
                return NULL;
        }

        if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
                return packet->trace->format->get_meta_section_option(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_HARDWARE);
        }
	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_option(packet,
			ERF_PROV_SECTION_MODULE, ERF_PROV_MODEL);
	}

	return NULL;
}
/* Get the hardware description for a meta packet.
 *
 * @params libtrace_packet_t meta packet to extract the hardware description from.
 * @params A pointer to a character buffer to store the hardware description in.
 * @params The size of the buffer passed in.
 * @returns Pointer to the character buffer containing the hardware description or NULL.
 */
char *trace_get_interface_hardware_description(libtrace_packet_t *packet, char *space,
	int spacelen) {

	libtrace_meta_t *r = trace_get_interface_hardware_description_meta(packet);
	if (r == NULL) { return NULL; }
	if (r->items[0].len > spacelen) {
		memcpy(space, r->items[0].data, spacelen);
	} else {
		memcpy(space, r->items[0].data, r->items[0].len);
	}
	trace_destroy_meta(r);
	return space;
}

/* Get any interface comments for a meta packet
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t packet
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_interface_comment_meta(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_comment()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_option(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_COMMENT);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_option(packet,
			PCAPNG_INTERFACE_TYPE, PCAPNG_OPTION_COMMENT);
	}

	return NULL;
}
/* Get the interface comment for a meta packet.
 * Note: ERF packets can contain multiple interfaces per meta packet. Use index to
 * specify the interface ID.
 *
 * @params libtrace_packet_t meta packet to extract the interface comment from.
 * @params A pointer to a character buffer to store the interface description in.
 * @params The size of the buffer passed in.
 * @params The interface number within the meta packet.
 * @returns Pointer to the character buffer containing the hardware description or NULL.
 */
char *trace_get_interface_comment(libtrace_packet_t *packet, char *space, int spacelen,
	int index) {

	libtrace_meta_t *r = trace_get_interface_comment_meta(packet);
	if (r == NULL) { return NULL; }
	if (index > r->num) { return NULL; }
	if (r->items[index].len > spacelen) {
		memcpy(space, r->items[index].data, spacelen);
	} else {
		memcpy(space, r->items[index].data, r->items[index].len);
	}
	trace_destroy_meta(r);
	return space;
}

/* Get the capture application for a meta packet
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t packet
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_capture_application_meta(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_comment()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
                return packet->trace->format->get_meta_section_option(packet,
                        ERF_PROV_SECTION_CAPTURE, ERF_PROV_APP_NAME);
        }
        if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
                return packet->trace->format->get_meta_section_option(packet,
                        PCAPNG_SECTION_TYPE, PCAPNG_META_SHB_USERAPPL);
        }

        return NULL;
}
/* Get the capture application for a meta packet.
 *
 * @params libtrace_packet_t meta packet to extract the application name from.
 * @params A pointer to a character buffer to store the application name in.
 * @params The size of the buffer passed in.
 * @returns Pointer to the character buffer containing the application name or NULL.
 */
char *trace_get_capture_application(libtrace_packet_t *packet, char *space, int spacelen) {
	libtrace_meta_t *r = trace_get_capture_application_meta(packet);
	if (r == NULL) { return NULL; }
	if (r->items[0].len > spacelen) {
		memcpy(space, r->items[0].data, spacelen);
	} else {
		memcpy(space, r->items[0].data, r->items[0].len);
	}
	trace_destroy_meta(r);
	return space;
}

/* Get a meta section option from a meta packet
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t packet
 * @params Section code
 * @params Option code
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_section_option(libtrace_packet_t *packet, uint32_t section_code,
	uint16_t option_code) {

	if (trace_meta_check_input(packet, "trace_get_custom_meta()")<0) {
                return NULL;
        }

	return packet->trace->format->get_meta_section_option(packet,
		section_code, option_code);
}

/* Get a section from a meta packet
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t packet
 * @params Section code
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_section(libtrace_packet_t *packet, uint32_t section_code) {
	if (trace_meta_check_input(packet, "trace_get_section()")<0) {
                return NULL;
        }

	return packet->trace->format->get_meta_section(packet, section_code);
}
