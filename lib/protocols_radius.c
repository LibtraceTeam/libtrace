/*
 *
 * Copyright (c) 2007-2020 The University of Waikato, Hamilton, New Zealand.
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

#include "libtrace_radius.h"
#include <stdlib.h>
#include <stdio.h>
#include "libtrace_int.h"

DLLEXPORT char *trace_get_radius_username(libtrace_radius_t *radius,
        uint32_t radrem, uint8_t *namelen) {

    libtrace_radius_avp_t *username;

    if ((username = trace_get_radius_avp(radius, radrem,
            LIBTRACE_RADIUS_USERNAME)) != NULL) {
        /* minus 2 for the avp header fields */
        *namelen = username->length - 2;
        return (char *)&username->data;
    }

    *namelen = 0;
    return NULL;

}

DLLEXPORT char *trace_get_radius_nas_identifier(libtrace_radius_t *radius,
        uint32_t radrem, uint8_t *naslen) {

    libtrace_radius_avp_t *nas_ident;

    if ((nas_ident = trace_get_radius_avp(radius, radrem,
            LIBTRACE_RADIUS_NAS_IDENT)) != NULL) {
        *naslen = nas_ident->length - 2;
        return (char *)&nas_ident->data;
    }

    *naslen = 0;
    return NULL;
}

DLLEXPORT libtrace_radius_t *trace_get_radius(libtrace_packet_t *packet,
        uint32_t *remaining) {

    void *payload;
    libtrace_radius_t *radius;
    uint8_t proto;
    uint32_t plen;

    payload = trace_get_transport(packet, &proto, remaining);
    if (payload == NULL) {
        return NULL;
    }

    plen = trace_get_payload_length(packet);

    switch (proto) {
        case TRACE_IPPROTO_TCP:
            payload = trace_get_payload_from_tcp((libtrace_tcp_t *)payload, remaining);
            break;
        case TRACE_IPPROTO_UDP:
            payload = trace_get_payload_from_udp((libtrace_udp_t *)payload, remaining);
            break;
        default:
            payload = NULL;
            break;
    }

    if (payload == NULL) {
        *remaining = 0;
        return NULL;
    }

    /* we can only assume that the payload is RADIUS here -- ideally the
     * caller will only pass in packets that they know are RADIUS (e.g. by
     * matching the known IP and port of a RADIUS server), but we can at least
     * do some basic sanity checks to rule out obvious non-RADIUS packets.
     */

    /* enough data for radius header? */
    if (plen < sizeof(libtrace_radius_t)) {
        return NULL;
    }

    /* does the length in the radius length field match the remaining data */
    radius = (libtrace_radius_t *)payload;
    if (ntohs(radius->length) == plen) {
        return radius;
    }

    return NULL;
}

DLLEXPORT libtrace_radius_avp_t *trace_get_radius_avp(
        libtrace_radius_t *radius, uint32_t remaining,
        libtrace_radius_avp_type type) {

    libtrace_radius_avp_t *c;
    uint8_t *ptr;
    uint32_t rem = ntohs(radius->length);

    if (rem <= sizeof(libtrace_radius_t)) {
        return NULL;
    }

    if (remaining < rem) {
        rem = remaining;
    }

    rem -= sizeof(libtrace_radius_t);

    ptr = (uint8_t *)radius + sizeof(libtrace_radius_t);

    while(1) {

        c = (libtrace_radius_avp_t *)ptr;

        if (c->type == type) {
            return c;
        }

        if (rem <= c->length) {
            return NULL;
        }

        rem -= c->length;
        ptr += c->length;
    }

    return NULL;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
