/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007-2012 The University of Waikato, Hamilton, 
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

#include "libtrace_int.h"
#include "libtrace.h"
#include "protocols.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h> // fprintf

DLLEXPORT void *trace_get_ospf_header(libtrace_packet_t *packet,
                uint8_t *version, uint32_t *remaining) {
        uint8_t proto;
        void *ospf;
        uint32_t dummy_rem = 0;


        if (!remaining)
                remaining = &dummy_rem;

        assert(version != NULL && "version may not be NULL when calling trace_get_ospf_header!");

        ospf = trace_get_transport(packet, &proto, remaining);

        if (!ospf || proto != TRACE_IPPROTO_OSPF || *remaining == 0)
                return NULL;

        *version = *((uint8_t *)ospf);

        if (*version == 2 && *remaining < sizeof(libtrace_ospf_v2_t))
                return NULL;

        return ospf;
}

DLLEXPORT void *trace_get_ospf_contents_v2(libtrace_ospf_v2_t *header,
                uint8_t *ospf_type, uint32_t *remaining) {

        uint8_t dummy_type;
        char *ptr;

        assert(remaining != NULL && "remaining may not be NULL when calling trace_get_ospf_contents!");

        if (!ospf_type)
                ospf_type = &dummy_type;

        if (!header || *remaining < sizeof(libtrace_ospf_v2_t)) {
                *ospf_type = 0;
                *remaining = 0;
                return NULL;
        }

        *ospf_type = header->type;

        ptr = ((char *)header) + sizeof(libtrace_ospf_v2_t);
        *remaining -= sizeof(libtrace_ospf_v2_t);

        return (void *)ptr;

}

DLLEXPORT unsigned char *trace_get_first_ospf_link_from_router_lsa_v2(
                libtrace_ospf_router_lsa_v2_t *lsa,
                uint32_t *remaining) {

        unsigned char *link_ptr = NULL;
        assert(remaining != NULL && "remaining may not be NULL when calling trace_get_first_link_from_router_lsa_v2!");

        if (!lsa || *remaining < sizeof(libtrace_ospf_router_lsa_v2_t)) {
                *remaining = 0;
                return NULL;
        }

        link_ptr = ((unsigned char *)lsa) + sizeof(libtrace_ospf_router_lsa_v2_t);
        *remaining -= sizeof(libtrace_ospf_router_lsa_v2_t);
        return link_ptr;

}

DLLEXPORT unsigned char *trace_get_first_ospf_lsa_from_db_desc_v2(
                libtrace_ospf_db_desc_v2_t *db_desc,
                uint32_t *remaining) {

        unsigned char *lsa_ptr = NULL;

        assert(remaining != NULL && "remaining may not be NULL when calling trace_get_first_ospf_v2_lsa!");

        if (!db_desc || *remaining < sizeof(libtrace_ospf_db_desc_v2_t)) {
                *remaining = 0;
                return NULL;
        }

        lsa_ptr = ((unsigned char *)db_desc) + sizeof(libtrace_ospf_db_desc_v2_t);
        *remaining -= sizeof(libtrace_ospf_db_desc_v2_t);

        return lsa_ptr;
}

DLLEXPORT unsigned char *trace_get_first_ospf_lsa_from_update_v2(
                libtrace_ospf_ls_update_t *ls_update,
                uint32_t *remaining) {

        unsigned char *lsa_ptr = NULL;

        assert(remaining != NULL && "remaining may not be NULL when calling trace_get_first_ospf_v2_lsa!");

        if (!ls_update || *remaining < sizeof(libtrace_ospf_ls_update_t)) {
                *remaining = 0;
                return NULL;
        }

        lsa_ptr = ((unsigned char *)ls_update) + sizeof(libtrace_ospf_ls_update_t);
        *remaining -= sizeof(libtrace_ospf_ls_update_t);

        return lsa_ptr;
}

DLLEXPORT uint32_t trace_get_ospf_metric_from_as_external_lsa_v2(
                libtrace_ospf_as_external_lsa_v2_t *as_lsa) {

        uint32_t metric = 0;

        assert(as_lsa);

        metric = as_lsa->metric_a << 16;
        metric |= (as_lsa->metric_b << 8);
        metric |= as_lsa->metric_c;

        return metric;
}

DLLEXPORT uint32_t trace_get_ospf_metric_from_summary_lsa_v2(
                libtrace_ospf_summary_lsa_v2_t *sum_lsa) {

        uint32_t metric = 0;

        assert(sum_lsa);

        metric = sum_lsa->metric_a << 16;
        metric |= (sum_lsa->metric_b << 8);
        metric |= sum_lsa->metric_c;

        return metric;
}

DLLEXPORT int trace_get_next_ospf_link_v2(unsigned char **current,
                libtrace_ospf_link_v2_t **link,
                uint32_t *remaining,
                uint32_t *link_len) {

        if (*current == NULL || *remaining < sizeof(libtrace_ospf_link_v2_t)) {
                *remaining = 0;
                *link = NULL;
                return 0;
        }

        *link = (libtrace_ospf_link_v2_t *)*current;

        /* XXX The spec allows for multiple metrics for a single link. This
         * approach won't support this, so we may need to be more intelligent
         * about this in future */
        *remaining -= sizeof(libtrace_ospf_link_v2_t);
        *link_len = sizeof(libtrace_ospf_link_v2_t);
        *current += sizeof(libtrace_ospf_link_v2_t);

        return 1;

}

DLLEXPORT int trace_get_next_ospf_lsa_header_v2(unsigned char **current,
                libtrace_ospf_lsa_v2_t **lsa_hdr,
                uint32_t *remaining,
                uint8_t *lsa_type,
                uint16_t *lsa_length) {

        int valid_lsa = 0;

        if (*current == NULL || *remaining < sizeof(libtrace_ospf_lsa_v2_t)) {
                *lsa_hdr = NULL;
                *remaining = 0;
                return 0;

        }

        *lsa_hdr = (libtrace_ospf_lsa_v2_t *)(*current);

        /* Check that the LSA type is valid */
        switch ((*lsa_hdr)->lsa_type) {
                case TRACE_OSPF_LS_ROUTER:
                case TRACE_OSPF_LS_NETWORK:
                case TRACE_OSPF_LS_SUMMARY:
                case TRACE_OSPF_LS_ASBR_SUMMARY:
                case TRACE_OSPF_LS_EXTERNAL:
                        valid_lsa = 1;
                        break;
        }

        /* This function is for reading LSA headers only, e.g. those in DB desc
         * or LS Ack packets. As such, I'm going to set the type and length to
         * values that should prevent anyone from trying to treat subsequent
         * payload as an LSA body */
        *lsa_type = 0;
        *lsa_length = sizeof(libtrace_ospf_lsa_v2_t);

        if (!valid_lsa) {
                *remaining = 0;
                return -1;
        }

        *remaining -= *lsa_length;
        *current += *lsa_length;

        if (remaining == 0) {
                /* No more LSAs */
                return 0;
        }
        return 1;
}

DLLEXPORT int trace_get_next_ospf_lsa_v2(unsigned char **current,
                libtrace_ospf_lsa_v2_t **lsa_hdr,
                unsigned char **lsa_body,
                uint32_t *remaining,
                uint8_t *lsa_type,
                uint16_t *lsa_length) {

        int valid_lsa = 0;

        if (*current == NULL || *remaining < sizeof(libtrace_ospf_lsa_v2_t)) {
                *lsa_hdr = NULL;
                *lsa_body = NULL;
                *remaining = 0;

                return 0;

        }

        *lsa_hdr = (libtrace_ospf_lsa_v2_t *)(*current);
        *lsa_type = (*lsa_hdr)->lsa_type;
        *lsa_length = ntohs((*lsa_hdr)->length);

        /* Check that the LSA type is valid */
        switch (*lsa_type) {
                case TRACE_OSPF_LS_ROUTER:
                case TRACE_OSPF_LS_NETWORK:
                case TRACE_OSPF_LS_SUMMARY:
                case TRACE_OSPF_LS_ASBR_SUMMARY:
                case TRACE_OSPF_LS_EXTERNAL:
                        valid_lsa = 1;
                        break;
        }

        if (*lsa_length > *remaining || !valid_lsa) {
                /* LSA is incomplete or an invalid type.
                 *
                 * If this occurs, you've probably managed to read something
                 * that is NOT a legit LSA */
                *remaining = 0;
                *lsa_body = NULL;
                return -1;
        }

        /* Some OSPF packets, e.g. LS ACKs, only contain LSA headers. If this
         * is the case, we'll set the body pointer to NULL so the caller 
         * can't read invalid data */
        if (*lsa_length == sizeof(libtrace_ospf_lsa_v2_t))
                *lsa_body = NULL;
        else
                *lsa_body = (*current + sizeof(libtrace_ospf_lsa_v2_t));

        *remaining -= *lsa_length;
        *current += *lsa_length;

        if (remaining == 0) {
                /* No more LSAs */
                return 0;
        }

        return 1;

}


