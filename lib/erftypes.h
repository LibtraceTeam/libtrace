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

#ifndef _ERFTYPES_H_
#define _ERFTYPES_H_

/** @file
 *
 * @brief Header file containing all the possible GPP record types
 *
 * @author Daniel Lawson
 * @author Perry Lorier
 * @author Shane Alcock
 *
 * @version $Id$
 */

/* GPP record type defines - these can indicate the header that immediately 
 * follows the ERF header and/or an adjustment to the layout of the ERF header
 * itself, e.g. due to the use of Coloring. 
 *
 * NOTE: "Color" refers to the concept of marking packets based on matching
 * a particular filter or classification */

#ifndef TYPE_LEGACY
#define TYPE_LEGACY             0	/**< Legacy */
#endif

#ifndef TYPE_HDLC_POS
#define TYPE_HDLC_POS           1	/**< PoS with HDLC framing */
#endif

#ifndef TYPE_ETH
#define TYPE_ETH                2	/**< Ethernet */
#endif

#ifndef TYPE_ATM
#define TYPE_ATM                3	/**< ATM Cell */
#endif

#ifndef TYPE_AAL5
#define TYPE_AAL5               4	/**< AAL5 Frame */
#endif

#ifndef TYPE_MC_HDLC
#define TYPE_MC_HDLC            5	/**< Multi-channel HDLC */
#endif

#ifndef TYPE_MC_RAW
#define TYPE_MC_RAW             6	/**< Multi-channel Raw link record */
#endif

#ifndef TYPE_MC_ATM
#define TYPE_MC_ATM             7	/**< Multi-channel ATM Cell */
#endif

#ifndef TYPE_MC_RAW_CHANNEL
#define TYPE_MC_RAW_CHANNEL     8	/**< Multi-channel Raw link data */
#endif

#ifndef TYPE_MC_AAL5
#define TYPE_MC_AAL5            9	/**< Multi-channel AAL5 */
#endif

/** PoS with HDLC framing and classification information in the loss counter
 *  field */
#ifndef TYPE_COLOR_HDLC_POS
#define TYPE_COLOR_HDLC_POS     10	
#endif

/** Ethernet with classification information in the loss counter field */
#ifndef TYPE_COLOR_ETH
#define TYPE_COLOR_ETH          11
#endif

/** Multi-channel AAL2 */
#ifndef TYPE_MC_AAL2
#define TYPE_MC_AAL2            12
#endif

/** IP counter ERF record */
#ifndef TYPE_IP_COUNTER
#define TYPE_IP_COUNTER         13
#endif

/** TCP flow counter ERF record */
#ifndef TYPE_TCP_FLOW_COUNTER
#define TYPE_TCP_FLOW_COUNTER   14
#endif

/** PoS with HDLC framing with DSM color information in the loss counter field*/
#ifndef TYPE_DSM_COLOR_HDLC_POS
#define TYPE_DSM_COLOR_HDLC_POS 15
#endif

/** Ethernet with DSM color information in the loss counter field */
#ifndef TYPE_DSM_COLOR_ETH
#define TYPE_DSM_COLOR_ETH      16
#endif

/** Multi-channel HDLC with classification information in the loss counter 
 *  field */
#ifndef TYPE_COLOR_MC_HDLC_POS
#define TYPE_COLOR_MC_HDLC_POS  17
#endif

/** AAL2 Frame */
#ifndef TYPE_AAL2
#define TYPE_AAL2               18
#endif

/** Colored PoS HDLC record with Hash load balancing */
#ifndef TYPE_COLOR_HASH_POS
#define TYPE_COLOR_HASH_POS	19
#endif

/** Colored Ethernet with Hash load balancing */
#ifndef TYPE_COLOR_HASH_ETH
#define TYPE_COLOR_HASH_ETH	20
#endif

/** Infiniband */
#ifndef TYPE_INFINIBAND
#define TYPE_INFINIBAND 	21
#endif

/** IPv4 */
#ifndef TYPE_IPV4
#define TYPE_IPV4		22
#endif

/** IPv6 */
#ifndef TYPE_IPV6
#define TYPE_IPV6		23
#endif

/** Raw link data, usually SONET or SDH */
#ifndef TYPE_RAW_LINK
#define TYPE_RAW_LINK		24
#endif

/** Padding record */
#ifndef TYPE_PAD
#define TYPE_PAD		48
#endif


#endif /* _ERFTYPES_H_ */
