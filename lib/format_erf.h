#ifndef FORMAT_ERF_H
#define FORMAT_ERF_H

#include "libtrace.h"

int erf_get_framing_length(const libtrace_packet_t *packet);
libtrace_linktype_t erf_get_link_type(const libtrace_packet_t *packet);
libtrace_direction_t erf_get_direction(const libtrace_packet_t *packet);
libtrace_direction_t erf_set_direction(libtrace_packet_t *packet, libtrace_direction_t direction);
uint64_t erf_get_erf_timestamp(const libtrace_packet_t *packet);
int erf_get_capture_length(const libtrace_packet_t *packet);
int erf_get_wire_length(const libtrace_packet_t *packet);
size_t erf_set_capture_length(libtrace_packet_t *packet, size_t size);

#endif
