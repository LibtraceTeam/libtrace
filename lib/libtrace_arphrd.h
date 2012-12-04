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

#ifndef LIBTRACE_ARPHRD_H_
#define LIBTRACE_ARPHRD_H_

/* This is just a copy, paste and rename job from net/if_arp.h
 * 
 * Unfortunately not all systems (MAC OS X!!) have all of the ARPHRD types
 * defined in their version of net/if_arp.h so, as per usual, we have to
 * include our own for portability.
 */

/* ARP protocol HARDWARE identifiers. */
#define LIBTRACE_ARPHRD_NETROM   0               /* From KA9Q: NET/ROM pseudo. */
#define LIBTRACE_ARPHRD_ETHER    1               /* Ethernet 10/100Mbps.  */
#define LIBTRACE_ARPHRD_EETHER   2               /* Experimental Ethernet.  */
#define LIBTRACE_ARPHRD_AX25     3               /* AX.25 Level 2.  */
#define LIBTRACE_ARPHRD_PRONET   4               /* PROnet token ring.  */
#define LIBTRACE_ARPHRD_CHAOS    5               /* Chaosnet.  */
#define LIBTRACE_ARPHRD_IEEE802  6               /* IEEE 802.2 Ethernet/TR/TB.  */
#define LIBTRACE_ARPHRD_ARCNET   7               /* ARCnet.  */
#define LIBTRACE_ARPHRD_APPLETLK 8               /* APPLEtalk.  */
#define LIBTRACE_ARPHRD_DLCI     15              /* Frame Relay DLCI.  */
#define LIBTRACE_ARPHRD_ATM      19              /* ATM.  */
#define LIBTRACE_ARPHRD_METRICOM 23              /* Metricom STRIP (new IANA id).  */
#define LIBTRACE_ARPHRD_IEEE1394 24              /* IEEE 1394 IPv4 - RFC 2734.  */
#define LIBTRACE_ARPHRD_EUI64            27              /* EUI-64.  */
#define LIBTRACE_ARPHRD_INFINIBAND       32              /* InfiniBand.  */

/* Dummy types for non ARP hardware */
#define LIBTRACE_ARPHRD_SLIP     256
#define LIBTRACE_ARPHRD_CSLIP    257
#define LIBTRACE_ARPHRD_SLIP6    258
#define LIBTRACE_ARPHRD_CSLIP6   259
#define LIBTRACE_ARPHRD_RSRVD    260             /* Notional KISS type.  */
#define LIBTRACE_ARPHRD_ADAPT    264
#define LIBTRACE_ARPHRD_ROSE     270
#define LIBTRACE_ARPHRD_X25      271             /* CCITT X.25.  */
#define LIBTRACE_ARPHRD_HWX25    272             /* Boards with X.25 in firmware.  */
#define LIBTRACE_ARPHRD_PPP      512
#define LIBTRACE_ARPHRD_CISCO    513             /* Cisco HDLC.  */
#define LIBTRACE_ARPHRD_HDLC     LIBTRACE_ARPHRD_CISCO
#define LIBTRACE_ARPHRD_LAPB     516             /* LAPB.  */
#define LIBTRACE_ARPHRD_DDCMP    517             /* Digital's DDCMP.  */
#define LIBTRACE_ARPHRD_RAWHDLC  518             /* Raw HDLC.  */
#define LIBTRACE_ARPHRD_TUNNEL   768             /* IPIP tunnel.  */
#define LIBTRACE_ARPHRD_TUNNEL6  769             /* IPIP6 tunnel.  */
#define LIBTRACE_ARPHRD_FRAD     770             /* Frame Relay Access Device.  */
#define LIBTRACE_ARPHRD_SKIP     771             /* SKIP vif.  */
#define LIBTRACE_ARPHRD_LOOPBACK 772             /* Loopback device.  */
#define LIBTRACE_ARPHRD_LOCALTLK 773             /* Localtalk device.  */
#define LIBTRACE_ARPHRD_FDDI     774             /* Fiber Distributed Data Interface. */
#define LIBTRACE_ARPHRD_BIF      775             /* AP1000 BIF.  */
#define LIBTRACE_ARPHRD_SIT      776             /* sit0 device - IPv6-in-IPv4.  */
#define LIBTRACE_ARPHRD_IPDDP    777             /* IP-in-DDP tunnel.  */
#define LIBTRACE_ARPHRD_IPGRE    778             /* GRE over IP.  */
#define LIBTRACE_ARPHRD_PIMREG   779             /* PIMSM register interface.  */
#define LIBTRACE_ARPHRD_HIPPI    780             /* High Performance Parallel I'face. */
#define LIBTRACE_ARPHRD_ASH      781             /* (Nexus Electronics) Ash.  */
#define LIBTRACE_ARPHRD_ECONET   782             /* Acorn Econet.  */
#define LIBTRACE_ARPHRD_IRDA     783             /* Linux-IrDA.  */
#define LIBTRACE_ARPHRD_FCPP     784             /* Point to point fibrechanel.  */
#define LIBTRACE_ARPHRD_FCAL     785             /* Fibrechanel arbitrated loop.  */
#define LIBTRACE_ARPHRD_FCPL     786             /* Fibrechanel public loop.  */
#define LIBTRACE_ARPHRD_FCFABRIC 787             /* Fibrechanel fabric.  */
#define LIBTRACE_ARPHRD_IEEE802_TR 800           /* Magic type ident for TR.  */
#define LIBTRACE_ARPHRD_IEEE80211 801            /* IEEE 802.11.  */
#define LIBTRACE_ARPHRD_IEEE80211_PRISM 802      /* IEEE 802.11 + Prism2 header.  */
#define LIBTRACE_ARPHRD_IEEE80211_RADIOTAP 803   /* IEEE 802.11 + radiotap header.  */
#define LIBTRACE_ARPHRD_IEEE802154 804           /* IEEE 802.15.4 header.  */
#define LIBTRACE_ARPHRD_IEEE802154_PHY 805       /* IEEE 802.15.4 PHY header.  */

#define LIBTRACE_ARPHRD_VOID       0xFFFF        /* Void type, nothing is known.  */
#define LIBTRACE_ARPHRD_NONE       0xFFFE        /* Zero header length.  */


#endif
