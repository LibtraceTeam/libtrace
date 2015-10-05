/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007-2015 The University of Waikato, Hamilton, 
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


#ifdef HAVE_PCAP
#include "config.h"

#ifndef HAVE_PCAP_OPEN_DEAD
#include <stdio.h>
#include <pcap.h>
#ifdef HAVE_PCAP_INT_H
# include <pcap-int.h>
#else
# error "Need pcap-int.h for declaration of pcap_t"
#endif
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
