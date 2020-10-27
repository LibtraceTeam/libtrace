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
#ifndef FORMAT_ERF_H
#define FORMAT_ERF_H

#include "libtrace.h"

/* ERF Section codes */
#define ERF_PROV_SECTION_CAPTURE 0xFF00
#define ERF_PROV_SECTION_HOST 0xFF01
#define ERF_PROV_SECTION_MODULE 0xFF02
#define ERF_PROV_SECTION_INTERFACE 0xFF03
#define ERF_PROV_SECTION_STREAM 0xFF08

/* ERF Provenance record tag type codes */
#define ERF_PROV_COMMENT 1
#define ERF_PROV_GEN_TIME 2
#define ERF_PROV_FCS_LEN 8
#define ERF_PROV_MASK_CIDR 10
#define ERF_PROV_ORG_NAME 11
#define ERF_PROV_NAME 12
#define ERF_PROV_DESCR 13
#define ERF_PROV_APP_NAME 16
#define ERF_PROV_OS 17
#define ERF_PROV_HOSTNAME 18
#define ERF_PROV_MODEL 20
#define ERF_PROV_FW_VERSION 21
#define ERF_PROV_SERIAL_NO 22
#define ERF_PROV_SNAPLEN 29
#define ERF_PROV_CARD_NUM 30
#define ERF_PROV_MODULE_NUM 31
#define ERF_PROV_STREAM_NUM 33
#define ERF_PROV_LOC_NAME 34
#define ERF_PROV_FILTER 36
#define ERF_PROV_FLOW_HASH_MODE 37
#define ERF_PROV_TUNNELING_MODE 38
#define ERF_PROV_MEM 40
#define ERF_PROV_ROTFILE_NAME 43
#define ERF_PROV_DEV_NAME 44
#define ERF_PROV_DEV_PATH 45
#define ERF_PROV_LOC_DESCR 46
#define ERF_PROV_APP_VERSION 47
#define ERF_PROV_CPU 49
#define ERF_PROV_CPU_PHYS_CORES 50
#define ERF_PROV_CPU_NUMA_NODES 51
#define ERF_PROV_DAG_VERSION 53
#define ERF_PROV_IF_NUM 64
#define ERF_PROV_IF_SPEED 66
#define ERF_PROV_IF_IPV4 67
#define ERF_PROV_IF_IPV6 68
#define ERF_PROV_IF_MAC 69
#define ERF_PROV_IF_SFP_TYPE 78
#define ERF_PROV_IF_RX_POWER 79
#define ERF_PROV_IF_TX_POWER 80
#define ERF_PROV_IF_LINK_STATUS 81
#define ERF_PROV_IF_PHY_MODE 82
#define ERF_PROV_IF_PORT_TYPE 83
#define ERF_PROV_IF_RX_LATENCY 84
#define ERF_PROV_STREAM_DROP 216
#define ERF_PROV_STREAM_BUF_DROP 217
#define ERF_PROV_CLK_SOURCE 384
#define ERF_PROV_CLK_STATE 385
#define ERF_PROV_CLK_THRESHOLD 386
#define ERF_PROV_CLK_CORRECTION 387
#define ERF_PROV_CLK_FAILURES 388
#define ERF_PROV_CLK_RESYNCS 389
#define ERF_PROV_CLK_PHASE_ERROR 390
#define ERF_PROV_CLK_INPUT_PULSES 391
#define ERF_PROV_CLK_REJECTED_PULSES 392
#define ERF_PROV_CLK_PHC_INDEX 393
#define ERF_PROV_CLK_PHC_OFFSET 394
#define ERF_PROV_CLK_TIMEBASE 395
#define ERF_PROV_CLK_DESCR 396
#define ERF_PROV_CLK_OUT_SOURCE 397
#define ERF_PROV_CLK_LINK_MODE 398
#define ERF_PROV_PTP_DOMAIN_NUM 399
#define ERF_PROV_PTP_STEPS_REMOVED 400
#define ERF_PROV_CLK_PORT_PROTO 414

/** @file
 *
 * @brief Header file defining functions that apply to all libtrace formats
 * that use the ERF record format, e.g. ERF, DAG 2.4, DAG 2.5
 *
 * @author Daniel Lawson
 * @author Perry Lorier
 * @author Shane Alcock
 *
 * @version $Id$
 *
 * Not too much detail required with these functions - this header file exists
 * solely to ensure that we don't have to duplicate the same code across 
 * multiple format modules.
 */

typedef struct dag_section_header {
        uint16_t type;
        uint16_t len;
} PACKED dag_sec_t;

struct dag_opthdr {
        uint16_t optcode;
        uint16_t optlen;
} PACKED;

int erf_get_framing_length(const libtrace_packet_t *packet);
libtrace_linktype_t erf_get_link_type(const libtrace_packet_t *packet);
libtrace_direction_t erf_get_direction(const libtrace_packet_t *packet);
libtrace_direction_t erf_set_direction(libtrace_packet_t *packet, libtrace_direction_t direction);
uint64_t erf_get_erf_timestamp(const libtrace_packet_t *packet);
int erf_get_capture_length(const libtrace_packet_t *packet);
int erf_get_wire_length(const libtrace_packet_t *packet);
size_t erf_set_capture_length(libtrace_packet_t *packet, size_t size);
int erf_is_color_type(uint8_t erf_type);

libtrace_meta_t *erf_get_all_meta(libtrace_packet_t *packet);

#endif
