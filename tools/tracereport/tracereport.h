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

#ifndef TRACEREPORT_H
#define TRACEREPORT_H

#include "lt_inttypes.h"

typedef struct {
	uint64_t count;
	uint64_t bytes;
} stat_t;

typedef enum {
	REPORT_TYPE_ERROR = 1,
	REPORT_TYPE_FLOW = 1 << 1,
	REPORT_TYPE_TOS = 1 << 2,
	REPORT_TYPE_PROTO = 1 << 3,
	REPORT_TYPE_PORT = 1 << 4,
	REPORT_TYPE_TTL = 1 << 5,
	REPORT_TYPE_TCPOPT = 1 << 6,
	REPORT_TYPE_NLP = 1 << 7,
	REPORT_TYPE_DIR = 1 << 8,
	REPORT_TYPE_ECN = 1 << 9,
	REPORT_TYPE_TCPSEG = 1 << 10,
	REPORT_TYPE_SYNOPT = 1 << 11,
	REPORT_TYPE_LOCALITY = 1 << 12,	/* No longer used by libtrace */
	REPORT_TYPE_MISC = 1 << 13,
	REPORT_TYPE_DROPS = 1<< 14
} report_type_t;

#endif
