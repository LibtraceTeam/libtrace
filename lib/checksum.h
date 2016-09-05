/*
 *
 * Copyright (c) 2007-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */
#ifndef LIBTRACE_CHECKSUM_H_
#define LIBTRACE_CHECKSUM_H_

#include <inttypes.h>
#include "libtrace.h"

uint32_t add_checksum(void *buffer, uint16_t length);
uint16_t finish_checksum(uint32_t total_sum);
uint16_t checksum_buffer(void *buffer, uint16_t length);
uint32_t ipv4_pseudo_checksum(libtrace_ip_t *ip);
uint32_t ipv6_pseudo_checksum(libtrace_ip6_t *ip);

#endif
