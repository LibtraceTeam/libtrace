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

/* Get the interface name/s
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t meta packet
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_interface_name(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_name()")<0) {
		return NULL;
	}

	/* get the result */
	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_item(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_NAME);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_item(packet,
			PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_NAME);
	}

	return NULL;
}

/* Get the interface MAC address/s
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t meta packet
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_interface_mac(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_mac()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_item(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_MAC);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_item(packet,
			PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_MAC);
	}

	return NULL;
}

/* Get the interface speed/s from a meta packet
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t packet
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_interface_speed(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_speed()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_item(packet,
                	ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_SPEED);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_item(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_SPEED);
	}

	return NULL;
}

/* Get the interface ipv4 address/s
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t meta packet
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_interface_ip4(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_ip4()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_item(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_IPV4);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_item(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_IP4);
	}

	return NULL;
}
libtrace_meta_t *trace_get_interface_ipv4(libtrace_packet_t *packet) {
	return trace_get_interface_ip4(packet);
}

/* Get the interface ipv6 address/s
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t meta packet
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_interface_ip6(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_ip6()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
                return packet->trace->format->get_meta_section_item(packet,
                        ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_IPV4);
        }
        if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
                return packet->trace->format->get_meta_section_item(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_IP4);
        }

	return NULL;
}
libtrace_meta_t *trace_get_interface_ipv6(libtrace_packet_t *packet) {
	return trace_get_interface_ip6(packet);
}

/* Get the interface description/s
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t meta packet
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_interface_description(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_description()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_item(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_DESCR);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_item(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_DESCR);
	}

	return NULL;
}

/* Get the interface number/s
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t meta packet
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_interface_num(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_num()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_item(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_NUM);
	}
	/* Note: pcapng doesnt provide this */

	return NULL;
}

/* Get the host OS
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t meta packet
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_host_os(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_host_os()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_item(packet,
                        ERF_PROV_SECTION_HOST, ERF_PROV_OS);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_item(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_OS);
	}

	return NULL;
}

/* Get the frame check sequence length
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t meta packet
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_interface_frame_check_sequence_length(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_frame_check_sequence_length()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_item(packet,
                        ERF_PROV_SECTION_INTERFACE, ERF_PROV_FCS_LEN);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_item(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_FCSLEN);
	}

	return NULL;
}

/* Get the hardware description
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t meta packet
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_interface_hardware_description(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_hardware_description()")<0) {
                return NULL;
        }

        if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
                return packet->trace->format->get_meta_section_item(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_HARDWARE);
        }
	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_item(packet,
			ERF_PROV_SECTION_MODULE, ERF_PROV_MODEL);
	}

	return NULL;
}

/* Get any interface comments for a meta packet
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t packet
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_interface_comment(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_comment()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		return packet->trace->format->get_meta_section_item(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_COMMENT);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		return packet->trace->format->get_meta_section_item(packet,
			PCAPNG_INTERFACE_TYPE, PCAPNG_OPTION_COMMENT);
	}

	return NULL;
}

/* Get the capture application for a meta packet
 * Must be destroyed with trace_destroy_meta()
 *
 * @params libtrace_packet_t packet
 * @returns Pointer to libtrace_meta_t structure or NULL
 */
libtrace_meta_t *trace_get_capture_application(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_comment()")<0) {
                return NULL;
        }

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
                return packet->trace->format->get_meta_section_item(packet,
                        ERF_PROV_SECTION_CAPTURE, ERF_PROV_APP_NAME);
        }
        if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
                return packet->trace->format->get_meta_section_item(packet,
                        PCAPNG_SECTION_TYPE, PCAPNG_META_SHB_USERAPPL);
        }

        return NULL;
}

/* Get meta section option from a meta packet
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

	return packet->trace->format->get_meta_section_item(packet,
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
