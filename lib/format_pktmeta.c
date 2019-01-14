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

/* Reads the interface name for a packet
 *
 * @params libtrace_packet_t packet
 * @returns A pointer to a NULL terminated string containing the interface name or NULL
 */
char *trace_get_interface_name(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_name()")<0) {
		return NULL;
	}

	void *ptr = NULL;

	/* cleanup any old results */
	if (packet->meta.interface_name != NULL) {
		free(packet->meta.interface_name);
		packet->meta.interface_name = NULL;
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
 * @returns A pointer to a MAC address within the packet or NULL
 */
void *trace_get_interface_mac(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_mac()")<0) {
                return NULL;
        }

	void *ptr = NULL;

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		ptr = packet->trace->format->get_meta_data(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_MAC);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		ptr = packet->trace->format->get_meta_data(packet,
			PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_MAC);
	}

	if (ptr != NULL) {
		packet->meta.interface_mac = ptr+sizeof(libtrace_meta_result_t);
		return packet->meta.interface_mac;
	}

	return NULL;
}

/* Gets the interface speed from a meta packet
 *
 * @params libtrace_packet_t packet
 * @returns A pointer to the uint64_t interface speed within the packet or NULL
 */
uint64_t *trace_get_interface_speed(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_speed()")<0) {
                return NULL;
        }

	void *ptr = NULL;

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		ptr = packet->trace->format->get_meta_data(packet,
                	ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_SPEED);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		ptr = packet->trace->format->get_meta_data(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_SPEED);
	}

	if (ptr != NULL) {
		uint64_t *intspeed = (uint64_t *)(ptr+sizeof(libtrace_meta_result_t));
		packet->meta.interface_speed = *intspeed;
		return &packet->meta.interface_speed;
	}

	return NULL;
}

/* Gets the interface ipv4 address from a meta packet
 *
 * @params libtrace_packet_t packet
 * @returns A pointer to the IP4 address field within the packet or NULL
 */
uint32_t *trace_get_interface_ip4(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_ip4()")<0) {
                return NULL;
        }

	void *ptr = NULL;

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		ptr = packet->trace->format->get_meta_data(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_IPV4);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		ptr = packet->trace->format->get_meta_data(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_IP4);
	}

	if (ptr != NULL) {
		uint32_t *intip4 = (uint32_t *)(ptr+sizeof(libtrace_meta_result_t));
		packet->meta.interface_ipv4 = *intip4;
		return &packet->meta.interface_ipv4;
	}

	return NULL;
}
uint32_t *trace_get_interface_ipv4(libtrace_packet_t *packet) {
	return trace_get_interface_ip4(packet);
}

void *trace_get_interface_ip6(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_ip6()")<0) {
                return NULL;
        }

	void *ptr = NULL;

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
                ptr = packet->trace->format->get_meta_data(packet,
                        ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_IPV4);
        }
        if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
                ptr = packet->trace->format->get_meta_data(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_IP4);
        }

	if (ptr != NULL) {
		packet->meta.interface_ipv6 = ptr+sizeof(libtrace_meta_result_t);
		return packet->meta.interface_ipv6;
	}

	return NULL;
}
void *trace_get_interface_ipv6(libtrace_packet_t *packet) {
	return trace_get_interface_ip6(packet);
}

/* Gets the interface description for a packet
 *
 * @params libtrace_packet_t packet
 * @returns A pointer to a NULL terminated interface description string or NULL
 */
char *trace_get_interface_description(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_description()")<0) {
                return NULL;
        }

	if (packet->meta.interface_description != NULL) {
		free(packet->meta.interface_description);
		packet->meta.interface_description = NULL;
	}

	void *ptr = NULL;

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		ptr = packet->trace->format->get_meta_data(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_DESCR);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		ptr = packet->trace->format->get_meta_data(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_DESCR);
	}

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

/* Gets the interface number for the packet
 *
 * @params libtrace_packet_t packet
 * @returns A void pointer to the beginning of a uint32_t interface number;
 */
uint32_t *trace_get_interface_num(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_num()")<0) {
                return NULL;
        }

	void *ptr = NULL;

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		ptr = packet->trace->format->get_meta_data(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_IF_NUM);
	}
	/* Note: pcapng doesnt provide this */

	if (ptr != NULL) {
		uint32_t *intnum = (uint32_t *)(ptr+sizeof(libtrace_meta_result_t));
		packet->meta.interface_num = *intnum;
		return &packet->meta.interface_num;
	}

	return NULL;
}

/* Gets the host OS from a packets originating interface
 *
 * @params libtrace_packet_t packet
 * @returns A pointer to a NULL terminated string or NULL
 */
char *trace_get_host_os(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_host_os()")<0) {
                return NULL;
        }

	if (packet->meta.host_os != NULL) {
		free(packet->meta.host_os);
		packet->meta.host_os = NULL;
	}

	void *ptr = NULL;

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		ptr = packet->trace->format->get_meta_data(packet,
                        ERF_PROV_SECTION_HOST, ERF_PROV_OS);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		ptr = packet->trace->format->get_meta_data(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_OS);
	}

	if (ptr != NULL) {
		libtrace_meta_result_t *result = (libtrace_meta_result_t *)ptr;
                packet->meta.host_os = malloc(ntohs(result->len)+1);
                packet->meta.host_os[ntohs(result->len)] = '\0';
                memcpy(packet->meta.host_os, ptr+sizeof(libtrace_meta_result_t),
                        ntohs(result->len));

		return packet->meta.host_os;
	}

	return NULL;
}

/* Gets the frame check sequence length from a packets originating interface
 *
 * @params libtrace_packet_t packet
 * @returns A uint32_t pointer containing the fcslen or NULL
 */
uint32_t *trace_get_interface_frame_check_sequence_length(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_frame_check_sequence_length()")<0) {
                return NULL;
        }

	void *ptr = NULL;

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		ptr = packet->trace->format->get_meta_data(packet,
                        ERF_PROV_SECTION_INTERFACE, ERF_PROV_FCS_LEN);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		ptr = packet->trace->format->get_meta_data(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_FCSLEN);
	}

	if (ptr != NULL) {

		if (packet->trace->format->type == TRACE_FORMAT_ERF) {
			uint32_t *val = (uint32_t *)(ptr+sizeof(libtrace_meta_result_t));
			packet->meta.interface_fcslen = *val;
		} else if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
			uint8_t *val = (uint8_t *)(ptr+sizeof(libtrace_meta_result_t));
			packet->meta.interface_fcslen = *val;
		}
		return &packet->meta.interface_fcslen;
	}

	return NULL;
}

char *trace_get_interface_hardware_description(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_hardware_description()")<0) {
                return NULL;
        }

	if (packet->meta.interface_hardware_desc != NULL) {
		free(packet->meta.interface_hardware_desc);
		packet->meta.interface_hardware_desc = NULL;
	}

	void *ptr = NULL;

        if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
                ptr = packet->trace->format->get_meta_data(packet,
                        PCAPNG_INTERFACE_TYPE, PCAPNG_META_IF_HARDWARE);
        }
	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		ptr = packet->trace->format->get_meta_data(packet,
			ERF_PROV_SECTION_MODULE, ERF_PROV_MODEL);
	}

	if (ptr != NULL) {
		libtrace_meta_result_t *result = (libtrace_meta_result_t *)ptr;
                packet->meta.interface_hardware_desc = malloc(ntohs(result->len)+1);
                packet->meta.interface_hardware_desc[ntohs(result->len)] = '\0';
                memcpy(packet->meta.interface_hardware_desc, ptr+sizeof(libtrace_meta_result_t),
                        ntohs(result->len));

                return packet->meta.interface_hardware_desc;
	}

	return NULL;
}

char *trace_get_interface_comment(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_comment()")<0) {
                return NULL;
        }

	if (packet->meta.interface_comment != NULL) {
		free(packet->meta.interface_comment);
		packet->meta.interface_comment = NULL;
	}

	void *ptr = NULL;

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
		ptr = packet->trace->format->get_meta_data(packet,
			ERF_PROV_SECTION_INTERFACE, ERF_PROV_COMMENT);
	}
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
		ptr = packet->trace->format->get_meta_data(packet,
			PCAPNG_INTERFACE_TYPE, PCAPNG_OPTION_COMMENT);
	}

	if (ptr != NULL) {
		libtrace_meta_result_t *result = (libtrace_meta_result_t *)ptr;
                packet->meta.interface_comment = malloc(ntohs(result->len)+1);
                packet->meta.interface_comment[ntohs(result->len)] = '\0';
                memcpy(packet->meta.interface_comment, ptr+sizeof(libtrace_meta_result_t),
                        ntohs(result->len));

                return packet->meta.interface_comment;
	}

	return NULL;
}

char *trace_get_capture_application(libtrace_packet_t *packet) {
	if (trace_meta_check_input(packet, "trace_get_interface_comment()")<0) {
                return NULL;
        }

	if (packet->meta.capture_application != NULL) {
		free(packet->meta.capture_application);
		packet->meta.capture_application = NULL;
	}

	void *ptr = NULL;

	if (packet->trace->format->type == TRACE_FORMAT_ERF) {
                ptr = packet->trace->format->get_meta_data(packet,
                        ERF_PROV_SECTION_CAPTURE, ERF_PROV_APP_NAME);
        }
        if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
                ptr = packet->trace->format->get_meta_data(packet,
                        PCAPNG_SECTION_TYPE, PCAPNG_META_SHB_USERAPPL);
        }

	if (ptr != NULL) {
                libtrace_meta_result_t *result = (libtrace_meta_result_t *)ptr;
                packet->meta.capture_application = malloc(ntohs(result->len)+1);
                packet->meta.capture_application[ntohs(result->len)] = '\0';
                memcpy(packet->meta.capture_application, ptr+sizeof(libtrace_meta_result_t),
                        ntohs(result->len));

                return packet->meta.capture_application;
        }

        return NULL;
}


