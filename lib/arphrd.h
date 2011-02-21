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


#ifndef ARPHRD_H_
#define ARPHRD_H_

/* Defines for various ARPHRD values, if needed */

#ifndef WIN32
#include <net/if_arp.h>
#endif

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER    1               /* Ethernet 10/100Mbps.  */
#endif

#ifndef ARPHRD_EETHER
#define ARPHRD_EETHER    2               /* Experimental Ethernet 10/100Mbps.  */
#endif

#ifndef ARPHRD_PPP
#define ARPHRD_PPP      512
#endif

#ifndef ARPHRD_LOOPBACK
#define ARPHRD_LOOPBACK 772
#endif

#ifndef ARPHRD_IEEE80211
#define ARPHRD_IEEE80211        801
#endif

#ifndef ARPHRD_NONE
#define ARPHRD_NONE     0xFFFE
#endif


#endif
