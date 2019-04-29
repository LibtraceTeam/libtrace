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

#ifdef HAVE_PCAP
#include "config.h"

#ifndef HAVE_PCAP_OPEN_DEAD
#include <stdio.h>
#include <pcap.h>
#include <string.h>

/* Custom implementation of pcap_open_dead as some versions of PCAP do not
 * have it */

pcap_t *pcap_open_dead(int linktype, int snaplen) {
    pcap_t *p = NULL;

    p = (pcap_t *)malloc(sizeof(*p));
    if (p == NULL)
        return NULL;    
    p->snapshot = snaplen;
    p->linktype = linktype;
    return p;
}
#endif
#endif
