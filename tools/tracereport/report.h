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


#ifndef REPORT_H
#define REPORT_H

void dir_per_packet(struct libtrace_packet_t *packet);
void error_per_packet(struct libtrace_packet_t *packet);
void flow_per_packet(struct libtrace_packet_t *packet);
void misc_per_packet(struct libtrace_packet_t *packet);
void port_per_packet(struct libtrace_packet_t *packet);
void protocol_per_packet(struct libtrace_packet_t *packet);
void tos_per_packet(struct libtrace_packet_t *packet);
void ttl_per_packet(struct libtrace_packet_t *packet);
void tcpopt_per_packet(struct libtrace_packet_t *packet);
void synopt_per_packet(struct libtrace_packet_t *packet);
void nlp_per_packet(struct libtrace_packet_t *packet);
void ecn_per_packet(struct libtrace_packet_t *packet);
void tcpseg_per_packet(struct libtrace_packet_t *packet);

void drops_per_trace(libtrace_t *trace);

void dir_report(void);
void error_report(void);
void flow_report(void);
void misc_report(void);
void port_report(void);
void protocol_report(void);
void tos_report(void);
void ttl_report(void);
void tcpopt_report(void);
void synopt_report(void);
void nlp_report(void);
void ecn_report(void);
void tcpseg_report(void);
void drops_report(void);

#endif
