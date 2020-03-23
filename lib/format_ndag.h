/*
 *
 * Copyright (c) 2007-2017 The University of Waikato, Hamilton, New Zealand.
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


#ifndef FORMAT_NDAG_H_
#define FORMAT_NDAG_H_

#include <libtrace.h>

#define NDAG_MAX_DGRAM_SIZE (8900)

#define NDAG_MAGIC_NUMBER (0x4E444147)
#define NDAG_EXPORT_VERSION 1

#define MAX_NETACQ_POLYGONS 8

enum {
        NDAG_PKT_BEACON = 0x01,
        NDAG_PKT_ENCAPERF = 0x02,
        NDAG_PKT_RESTARTED = 0x03,
        NDAG_PKT_ENCAPRT = 0x04,
        NDAG_PKT_KEEPALIVE = 0x05,
        NDAG_PKT_CORSAROTAG = 0x06
};

/** Must match the ipmeta_provider_id_t enum in libipmeta */
enum {
        NDAG_IPMETA_PROVIDER_MAXMIND = 1,
        NDAG_IPMETA_PROVIDER_NETACQ_EDGE = 2,
        NDAG_IPMETA_PROVIDER_PFX2AS = 3,
};

/** A set of tags that have been derived for an individual packet. */
typedef struct corsaro_packet_tags {

    /** A bitmap that is used to identify which libipmeta tags are
     *  valid, i.e. which providers were enabled.
     */
    uint32_t providers_used;

    /** The ID of the geo-location region for the source IP, as
     *  determined using the netacq-edge data */
    uint16_t netacq_region;

    /** The ID of the geo-location 'polygon' for the source IP, as
     *  determined using the netacq-edge data. Note that there can
     *  be multiple polygons for a single packet, as there are
     *  multiple sources of polygon data. */
    uint32_t netacq_polygon[MAX_NETACQ_POLYGONS];

    /** The ASN that owns the source IP, according to the prefix2asn
     *  data. */
    uint32_t prefixasn;

    /** The 2-letter code describing the geo-location country
     *  for the source IP, as determined using the maxmind data.
     *  Encoded as a uint16_t, one byte for each character. */
    uint16_t maxmind_country;

    /** The 2-letter code describing the geo-location country
     *  for the source IP, as determined using the netacq-edge data.
     *  Encoded as a uint16_t, one byte for each character. */
    uint16_t netacq_country;

    /** The source port used by the packet */
    uint16_t src_port;

    /** The destiantion port used by the packet */
    uint16_t dest_port;

    /** The 2-letter code describing the geo-location continent
     *  for the source IP, as determined using the maxmind data.
     *  Encoded as a uint16_t, one byte for each character. */
    uint16_t maxmind_continent;

    /** The 2-letter code describing the geo-location continent
     *  for the source IP, as determined using the netacq-edge data.
     *  Encoded as a uint16_t, one byte for each character. */
    uint16_t netacq_continent;

    /** Bitmask showing which filters this packet matches, i.e.
     * is it spoofed, is it erratic, is it non-routable */
    uint64_t filterbits;

    /** The hash of the flowtuple ID for this packet -- note this is more
     *  than just a standard 5-tuple and includes fields such as TTL,
     *  IP length, TCP flags etc.
     */
    uint32_t ft_hash;

    /** The post-IP protocol used by the packet */
    uint8_t protocol;
} PACKED corsaro_packet_tags_t;


/** Meta-data that is sent in advance of any published packets, including
 *  the tags that were applied to the packet.
 */
typedef struct corsaro_tagged_packet_header {
    uint8_t hashbin;

    /** Bitmask showing which filters were matched by the packet.
     *  MUST be the second field in this structure so that zeromq
     *  subscription filtering can be applied properly.
     */
    uint16_t filterbits;

    /** The seconds portion of the packet timestamp */
    uint32_t ts_sec;

    /** The microseconds portion of the packet timestamp */
    uint32_t ts_usec;

    /** The length of the packet, starting from the Ethernet header */
    uint16_t pktlen;

    uint16_t wirelen;

    uint32_t tagger_id;

    uint64_t seqno;

    /** The tags that were applied to this packet by the tagging module */
    corsaro_packet_tags_t tags;
} PACKED corsaro_tagged_packet_header_t;

/* == Protocol header structures == */

/* Common header -- is prepended to all exported records */
typedef struct ndag_common_header {
        uint32_t magic;
        uint8_t version;
        uint8_t type;
        uint16_t monitorid;
} PACKED ndag_common_t;

/* Beacon -- structure is too simple to be worth defining as a struct */
/*
 * uint16_t numberofstreams;
 * uint16_t firststreamport;
 * uint16_t secondstreamport;
 * ....
 * uint16_t laststreamport;
 */

/* Encapsulation header -- used by both ENCAPERF and ENCAPRT records */
typedef struct ndag_encap {
        uint64_t started;
        uint32_t seqno;
        uint16_t streamid;
        uint16_t recordcount; /* acts as RT type for ENCAPRT records */
} PACKED ndag_encap_t;

#endif
