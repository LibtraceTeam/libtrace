/*
 *
 * Copyright (c) 2023, Shane Alcock.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * Libtrace was originally developed by the University of Waikato WAND
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

#ifndef LIBTRACE_FORMAT_ETSI_H_
#define LIBTRACE_FORMAT_ETSI_H_

#include "libtrace.h"

uint64_t etsilive_get_erf_timestamp(const libtrace_packet_t *packet);
int etsilive_get_framing_length(const libtrace_packet_t *packet UNUSED);
libtrace_linktype_t etsilive_get_link_type(
                const libtrace_packet_t *packet UNUSED);
int etsilive_get_pdu_length(const libtrace_packet_t *packet) ;

#endif
