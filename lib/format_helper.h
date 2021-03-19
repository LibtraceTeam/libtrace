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
#ifndef FORMAT_HELPER_H
#define FORMAT_HELPER_H
#include "common.h"
#include "wandio.h"

/** @file
 *
 * @brief Header file containing prototypes for functions that are useful for
 * multiple format modules
 *
 * @author Daniel Lawson
 * @author Perry Lorier
 * @author Shane Alcock
 *
 * @version $Id$
 */

/** Generic event function for a live capture device
 *
 * @param trace 	The input trace for the live capture device
 * @param packet	A libtrace packet to read the next available packet 
 * 			into
 * @return A libtrace event describing the next event of interest
 *
 * Any live capture format that does not require a custom event handler
 * should use this function.
 */
struct libtrace_eventobj_t trace_event_device(libtrace_t *trace, libtrace_packet_t *packet);

/** Generic event function for a offline trace file
 *
 * @param trace		The input trace for the trace file
 * @param packet	A libtrace packet to read the next available packet 
 * 			into
 * @return A libtrace event describing the next event of interest 
 *
 * Any trace file format that does not require a custom event handler should
 * use this function
 */
struct libtrace_eventobj_t trace_event_trace(libtrace_t *trace, libtrace_packet_t *packet);

/** Opens an input trace file for reading
 *
 * @param libtrace	The input trace to be opened
 * @return A libtrace IO reader for the newly opened file or NULL if the file
 * was unable to be opened
 */
io_t *trace_open_file(libtrace_t *libtrace);

/** Opens an output trace file for writing
 *
 * @param libtrace	The output trace to be opened
 * @param compress_type	The compression type to use when writing
 * @param level		The compression level to use when writing, ranging from
 * 			0 to 9
 * @param filemode	The file status flags for the file, bitwise-ORed.
 * @return A libtrace IO writer for the newly opened file or NULL if the file
 * was unable to be opened
 */
iow_t *trace_open_file_out(libtrace_out_t *libtrace,
		int compress_type,
		int level,
		int filemode);

/** Determines the number of cores available on the host.
 *
 * @return The number of cores detected by this function.
 */
uint32_t trace_get_number_of_cores(void);

/** Attempts to determine the direction for a pcap (or pcapng) packet.
 *
 * @param packet        The packet in question.
 * @return A valid libtrace_direction_t describing the direction that the
 *         packet was travelling, if direction can be determined. Otherwise
 *         returns TRACE_DIR_UNKNOWN.
 *
 * Note that we can determine the direction for only certain types of packets
 * if they are captured using pcap/pcapng, specifically SLL and PFLOG captures.
 */
libtrace_direction_t pcap_get_direction(const libtrace_packet_t *packet);

#endif /* FORMAT_HELPER_H */
