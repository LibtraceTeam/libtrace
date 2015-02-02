/*
 * This file is part of libtrace
 *
 * Copyright (c) 2014 The University of Waikato, Hamilton, New Zealand.
 *
 * Authors: Perry Lorier
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
 */
#include <stdlib.h>
#include "libtrace.h"

void *trace_get_payload_from_vxlan(libtrace_vxlan_t *vxlan, uint32_t *remaining)
{
    if (remaining) {
        if (*remaining < sizeof(*vxlan)) {
            *remaining = 0;
            return NULL;
        }

        *remaining -= sizeof(*vxlan);
    }

    return (void*)((char *)vxlan + sizeof(*vxlan));
}


libtrace_vxlan_t *trace_get_vxlan_from_udp(libtrace_udp_t *udp,
        uint32_t *remaining)
{
    if (udp->dest != htons(4789)) { /* UDP port number for vxlan */
        return NULL; /* Not a vxlan packet. */
    }

    return trace_get_payload_from_udp(udp, remaining);
}



