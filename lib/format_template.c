/*
 * This file is part of libtrace
 *
 * Copyright (c) 2004 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson 
 *          Perry Lorier 
 *          
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libtrace; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 *
 */

#include "libtrace.h"
#include "format.h"
#include <inttypes.h>

static int template_init_input(struct libtrace_t *libtrace) {
	return -1;
}

static int template_init_output(struct libtrace_out_t *libtrace) {
	return -1;
}

static int template_config_output(struct libtrace_out_t *libtrace, int argc, char *argv[]) {
	return -1;
}

static int template_fin_input(struct libtrace_t *libtrace) {
	return -1;
}

static int template_fin_output(struct libtrace_out_t *libtrace) {
	return -1;
}

static int template_read(struct libtrace_t *libtrace, void *buffer, size_t len) {
	return -1;
}
static int template_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	return -1;
}

static int template_write_packet(struct libtrace_out_t *libtrace, struct libtrace_packet_t *packet) {
	return -1;
}

static void *template_get_link(const struct libtrace_packet_t *packet) {
	return NULL;
}

static libtrace_linktype_t template_get_link_type(const struct libtrace_packet_t *packet) {
	return -1;
}

static int8_t template_get_direction(const struct libtrace_packet_t *packet) {
	return -1;
}

static int8_t template_set_direction(const struct libtrace_packet_t *packet, int8_t direction) {
	return -1;
}

static uint64_t template_get_erf_timestamp(const struct libtrace_packet_t *packet) {
	return -1;
}

static struct timeval template_get_timeval(const struct libtrace_packet_t *packet) { 
	struct timeval tv;
	return tv;
}

static double template_get_seconds(const struct libtrace_packet_t *packet) {
	return -1;
}

static int template_get_capture_length(const struct libtrace_packet_t *packet) {
	return -1;
}

static int template_get_wire_length(const struct libtrace_packet_t *packet) {
	return -1;
}

static size_t template_set_capture_length(const struct libtrace_packet_t *packet,size_t size) {
	return -1;
}

static void template_help() {
	return;
}
static struct format_t template = {
	"template",
	"$Id$",
	template_init_input,	 	/* init_input */
	template_init_output,		/* init_output */
	template_config_output,		/* config_output */
	template_fin_input,		/* fin_input */
	template_fin_output,		/* fin_output */
	template_read,			/* read */
	template_read_packet,		/* read_packet */
	template_write_packet,		/* write_packet */
	template_get_link,		/* get_link */
	template_get_link_type,		/* get_link_type */
	template_get_direction,		/* get_direction */
	template_set_direction,		/* set_direction */
	template_get_erf_timestamp,	/* get_erf_timestamp */
	template_get_timeval,		/* get_timeval */
	template_get_seconds,		/* get_seconds */
	template_get_capture_length,	/* get_capture_length */
	template_get_wire_length,	/* get_wire_length */
	template_set_capture_length,	/* set_capture_length */
	template_help			/* help */
};

void __attribute__((constructor)) template_constructor() {
	register_format(&template);
}
