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

#ifndef LIBTRACE_RADIUS_H_
#define LIBTRACE_RADIUS_H_

#include "libtrace.h"

/** See protocols_radius.c for implementation of the methods declared in this
 *  header file.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** Enumeration of all valid RADIUS codes */
typedef enum {
    LIBTRACE_RADIUS_ACCESS_REQUEST = 1,
    LIBTRACE_RADIUS_ACCESS_ACCEPT = 2,
    LIBTRACE_RADIUS_ACCESS_REJECT = 3,
    LIBTRACE_RADIUS_ACCOUNTING_REQUEST = 4,
    LIBTRACE_RADIUS_ACCOUNTING_RESPONSE = 5,
    LIBTRACE_RADIUS_ACCESS_CHALLENGE = 11,
    LIBTRACE_RADIUS_STATUS_SERVER = 12,
    LIBTRACE_RADIUS_STATUS_CLIENT = 13,
    LIBTRACE_RADIUS_DISCONNECT_REQUEST = 40,
    LIBTRACE_RADIUS_DISCONNECT_ACK = 41,
    LIBTRACE_RADIUS_DISCONNECT_NAK = 42,
    LIBTRACE_RADIUS_COA_REQUEST = 43,
    LIBTRACE_RADIUS_COA_ACK = 44,
    LIBTRACE_RADIUS_COA_NAK = 45,
    LIBTRACE_RADIUS_RESERVED = 255
} PACKED libtrace_radius_code;

/** Enumeration of Attribute Value Pair types (incomplete) */
typedef enum {
    LIBTRACE_RADIUS_USERNAME = 1,
    LIBTRACE_RADIUS_USER_PASSWORD = 2,
    LIBTRACE_RADIUS_CHAP_PASSWORD = 3,
    LIBTRACE_RADIUS_NAS_IP_ADDRESS = 4,
    LIBTRACE_RADIUS_NAS_PORT = 5,
    LIBTRACE_RADIUS_SERVICE_TYPE = 6,
    LIBTRACE_RADIUS_FRAMED_PROTOCOL = 7,
    LIBTRACE_RADIUS_FRAMED_IP_ADDRESS = 8,
    LIBTRACE_RADIUS_FRAMED_IP_NETMASK = 9,
    LIBTRACE_RADIUS_FRAMED_ROUTING = 10,
    LIBTRACE_RADIUS_FRAMED_FILTER_ID = 11,
    LIBTRACE_RADIUS_FRAMED_MTU = 12,
    LIBTRACE_RADIUS_FRAMED_COMPRESSION = 13,
    LIBTRACE_RADIUS_LOGIN_IP_HOST = 14,
    LIBTRACE_RADIUS_LOGIN_SERVICE = 15,
    LIBTRACE_RADIUS_LOGIN_TCP_PORT = 16,
    LIBTRACE_RADIUS_LOGIN_REPLY_MESSAGE = 18,
    LIBTRACE_RADIUS_LOGIN_CALLBACK_NUMBER = 19,
    LIBTRACE_RADIUS_LOGIN_CALLBACK_ID = 20,
    LIBTRACE_RADIUS_FRAMED_ROUTE = 22,
    LIBTRACE_RADIUS_FRAMED_IPX_NETWORK = 23,
    LIBTRACE_RADIUS_STATE = 24,
    LIBTRACE_RADIUS_CLASS = 25,
    LIBTRACE_RADIUS_VENDOR_SPECIFIC = 26,
    LIBTRACE_RADIUS_SESSION_TIMEOUT = 27,
    LIBTRACE_RADIUS_IDLE_TIMEOUT = 28,
    LIBTRACE_RADIUS_TERMINATION_ACTION = 29,
    LIBTRACE_RADIUS_CALLED_STATION_ID = 30,
    LIBTRACE_RADIUS_CALLING_STATION_ID = 31,
    LIBTRACE_RADIUS_NAS_IDENT = 32,
    LIBTRACE_RADIUS_PROXY_STATE = 33,
    LIBTRACE_RADIUS_LOGIN_LAT_SERVICE = 34,
    LIBTRACE_RADIUS_LOGIN_LAT_NODE = 35,
    LIBTRACE_RADIUS_LOGIN_LAT_GROUP = 36,
    LIBTRACE_RADIUS_FRAMED_APPLETALK_LINK = 37,
    LIBTRACE_RADIUS_FRAMED_APPLETALK_NETWORK = 38,
    LIBTRACE_RADIUS_FRAMED_APPLETALK_ZONE = 39,
    LIBTRACE_RADIUS_ACCT_STATUS_TYPE = 40,
    LIBTRACE_RADIUS_ACCT_DELAY_TIME = 41,
    LIBTRACE_RADIUS_ACCT_INPUT_OCTETS = 42,
    LIBTRACE_RADIUS_ACCT_OUTPUT_OCTETS = 43,
    LIBTRACE_RADIUS_ACCT_SESSION_ID = 44,
    LIBTRACE_RADIUS_ACCT_AUTHENTIC = 45,
    LIBTRACE_RADIUS_ACCT_SESSION_TIME = 46,
    LIBTRACE_RADIUS_ACCT_INPUT_PACKETS = 47,
    LIBTRACE_RADIUS_ACCT_OUTPUT_PACKETS = 48
} PACKED libtrace_radius_avp_type;

/** Structure representing a RADIUS AVP */
typedef struct libtrace_radius_avp {
    /** The AVP type */
    libtrace_radius_avp_type type;
    /** The AVP length, including the type and length fields */
    uint8_t length;
    /** The first byte of the value of the AVP */
    char data;
} PACKED libtrace_radius_avp_t;

/** A RADIUS message header */
typedef struct libtrace_radius {
    /** The type of RADIUS message */
    libtrace_radius_code code;
    /** A identifier that is used to match requests with their corresponding
     *  replies.
     */
    uint8_t identifier;
    /** The length of the RADIUS message, including this header */
    uint16_t length;
    /** Used to encrypt passwords and validate replies */
    uint64_t authenticator[2];
} PACKED libtrace_radius_t;

/** Returns a pointer to the start of the RADIUS message header, if there
 *  is potentially one inside the given packet.
 *
 *  Note that there is no easy way for libtrace to tell if a packet is
 *  RADIUS or not, so it is up to the user to avoid passing non-RADIUS
 *  packets into this function where possible.
 *
 *  This function will use some heuristics to recognise non-RADIUS packets,
 *  e.g. if the RADIUS "length" field does not match the payload size of the
 *  packet then we assume it is not a RADIUS packet and return NULL.
 *
 *  @param packet           The libtrace packet to be processed
 *  @param [out]remaining   Updated to contain the number of bytes remaining
 *                          from the start of the RADIUS header.
 *
 *  @return NULL if no RADIUS header is present, otherwise a pointer to
 *          where the RADIUS header should be.
 */
DLLEXPORT libtrace_radius_t *trace_get_radius(libtrace_packet_t *packet,
        uint32_t *remaining);

/** Searches for a specific AVP within a RADIUS message.
 *
 *  @param radius       The RADIUS message to be searched
 *  @param remaining    The number of bytes remaining in the RADIUS message,
 *                      as reported by trace_get_radius()
 *  @param type         The AVP type to search for
 *
 *  @return A pointer to the first AVP that has matches the given type, or
 *          NULL if that AVP type is not present in the packet.
 */
DLLEXPORT libtrace_radius_avp_t *trace_get_radius_avp(
        libtrace_radius_t *radius, uint32_t remaining,
        libtrace_radius_avp_type type);

/** Returns the value of the Username AVP in a RADIUS message.
 *
 *  @param radius           The RADIUS message to be parsed for a username
 *  @param radrem           The number of bytes remaining in the RADIUS message,
 *                          as reported by trace_get_radius()
 *  @param [out]name_len    Set to the length of the username that was found.
 *
 *  @return a pointer to a character string (non-null-terminated) that contains
 *          the Username from the RADIUS packet, or NULL if no Username was
 *          found.
 */
DLLEXPORT char *trace_get_radius_username(libtrace_radius_t *radius,
        uint32_t radrem, uint8_t *name_len);

/** Returns the value of the NAS identifier in a RADIUS message.
 *
 *  @param radius           The RADIUS message to be parsed for an identifier
 *  @param radrem           The number of bytes remaining in the RADIUS message,
 *                          as reported by trace_get_radius()
 *  @param [out]naslen      Set to the length of the identifier that was found.
 *
 *  @return a pointer to a character string (non-null-terminated) that contains
 *          the NAS identifier from the RADIUS packet, or NULL if no NAS
 *          identifier was found.
 */
DLLEXPORT char *trace_get_radius_nas_identifier(libtrace_radius_t *radius,
        uint32_t radrem, uint8_t *naslen);

#ifdef __cplusplus
} /* extern "C" */
#endif /* #ifdef __cplusplus */


#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
