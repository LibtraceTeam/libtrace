/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Daniel Lawson 
 *          Perry Lorier
 *          Shane Alcock 
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


/** @file
 *
 * @brief Protocol access functions that have not yet been made available
 * through the external API.
 *
 * These are protocol decoders that haven't yet seen enough use to consider
 * their API stable enough to move into libtrace.h where they probably belong.
 */


/* These are generally used by the next higher level, so really we should
 * be defining API's that mean that these don't need to be known by the
 * higher level.
 */

#include "libtrace.h"
/* pkt meta headers */

/* l2 headers */

/** Gets a pointer to the payload following an Ethernet header
 *
 * @param ethernet	A pointer to the Ethernet header
 * @param[out] type	Set to contain the Ethernet type of the next header
 * @param[in, out] remaining	Updated with the number of captured bytes
 * 				remaining
 * @return A pointer to the header following the provided Ethernet header, or
 * NULL if no subsequent header is present.
 *
 * Remaining must point to the number of bytes captured from the Ethernet header
 * and beyond.  It will be decremented by the number of bytes skipped to find
 * the payload.
 *
 * If the Ethernet header is complete but there are zero bytes of payload after 
 * the end of the header, a pointer to where the payload would be is returned 
 * and remaining will be set to 0.  If the Ethernet header is incomplete 
 * (truncated), then NULL is returned and remaining will be set to 0. 
 * Therefore, it is very important to check the value of remaining after
 * calling this function.
 *
 * @note \ref trace_get_payload_from_layer2 provides a suitable alternative that is
 * actually available via the external API
 */
void *trace_get_payload_from_ethernet(void *ethernet, 
		uint16_t *type,
		uint32_t *remaining);

/* l3 definitions */

/** Ports structure used to get the source and destination ports for transport
 * protocols */
struct ports_t {
	uint16_t src;		/**< Source port */
	uint16_t dst;		/**< Destination port */
};


