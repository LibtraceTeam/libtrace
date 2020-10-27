/*
 *
 * Copyright (c) 2007-2019 The University of Waikato, Hamilton, New Zealand.
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

#ifndef LIBTRACE_TRACEANON_H_
#define LIBTRACE_TRACEANON_H_

#include "../tools_yaml.h"

enum enc_type_t {
        ENC_NONE,
        ENC_CRYPTOPAN,
        ENC_PREFIX_SUBSTITUTION
};

#define SALT_LENGTH 32
#define SHA256_SIZE 32

typedef struct traceanon_port_list_t traceanon_port_list_t;

struct traceanon_port_list_t {
        uint16_t port;
        traceanon_port_list_t *nextport;
};

typedef struct traceanon_radius_server_t {
        struct in_addr ipaddr;
        traceanon_port_list_t *port;
} traceanon_radius_server_t;

typedef struct radius_header {
    uint8_t code;
    uint8_t identifier;
    uint16_t length;
    uint8_t auth[16];
} PACKED radius_header_t;

typedef struct radius_avp {
    uint8_t type;
    uint8_t length;
    uint8_t value;
} PACKED radius_avp_t;

typedef struct traceanon_options {

    bool enc_source_opt;
    bool enc_dest_opt;
    enum enc_type_t enc_type;
    char *enc_key;

    bool enc_radius_packet;
    bool radius_force_anon;
    uint8_t salt[SALT_LENGTH];
    bool isSaltSet;
    traceanon_radius_server_t radius_server;

    int level;
    trace_option_compresstype_t compress_type;
    int threads;
    char *filterstring;
    char *outputuri;

} traceanon_opts_t;

#ifdef __cplusplus
extern "C" {
#endif

int traceanon_yaml_parser(void *arg, yaml_document_t *doc,
        yaml_node_t *key, yaml_node_t *value);

#ifdef __cplusplus
}
#endif

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
