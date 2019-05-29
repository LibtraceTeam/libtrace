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

#include "../tools_yaml.h"
#include "traceanon.h"

#include <arpa/inet.h>

static inline void add_port_to_server(traceanon_radius_server_t *server,
        uint16_t port ){
    traceanon_port_list_t *currPort;
    currPort = (traceanon_port_list_t*) malloc(sizeof(traceanon_port_list_t));
    currPort->port = port;
    currPort->nextport = server->port;
    server->port = currPort;
}

static int parse_radius_section(traceanon_opts_t *opts, yaml_document_t *doc,
        yaml_node_t *anonip) {

    yaml_node_pair_t *pair;
    for (pair = anonip->data.mapping.pairs.start;
            pair < anonip->data.mapping.pairs.top; pair ++) {

        yaml_node_t *key, *value;

        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "encode_radius")
                        == 0) {
            if (yaml_parse_onoff((char *)value->data.scalar.value) == 1) {
                opts->enc_radius_packet = true;
            } else {
                opts->enc_radius_packet = false;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "ignore_safe_avps")
                        == 0) {
            if (yaml_parse_onoff((char *)value->data.scalar.value) == 1) {
                opts->radius_force_anon = false;
            } else {
                opts->radius_force_anon = true;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "salt")
                        == 0) {
            int saltlen = strlen((char *)value->data.scalar.value);

            if (saltlen > 32) {
                fprintf(stderr, "RADIUS salt is longer than 32 bytes, truncating.\n");
                saltlen = 32;
            }
            memcpy(opts->salt, value->data.scalar.value, saltlen);
            opts->isSaltSet = true;
        }

        /* TODO make this support IPv6 servers as well! */
        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "server")
                        == 0) {
            char *valstr = (char *)value->data.scalar.value;
            char *garbage;
            char *token = strtok(valstr, ",");
            struct in_addr ipaddr;

            if (inet_aton(token, &ipaddr) == 0){
                fprintf(stderr, "RADIUS server IP address malformed\n");
                return -1;
            }
            opts->radius_server.ipaddr = ipaddr;

            garbage = NULL;
            while( (token = strtok(NULL, ",")) != NULL ) {
                in_port_t port = strtol(token, &garbage, 10);
                if (garbage == NULL || (*garbage != ',' && *garbage != 0)){
                    fprintf(stderr, "RADIUS port list malformed\n");
                    return -1;
                }
                add_port_to_server(&(opts->radius_server),htons(port));
            }
        }
    }
    return 0;
}

static int parse_anonip_section(traceanon_opts_t *opts, yaml_document_t *doc,
        yaml_node_t *anonip) {

    yaml_node_pair_t *pair;
    for (pair = anonip->data.mapping.pairs.start;
            pair < anonip->data.mapping.pairs.top; pair ++) {

        yaml_node_t *key, *value;

        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "encode_addresses")
                        == 0) {
            char *valstr = (char *)value->data.scalar.value;

            if (strcmp(valstr, "both") == 0) {
                opts->enc_source_opt = true;
                opts->enc_dest_opt = true;
            } else if (strcmp(valstr, "source") == 0) {
                opts->enc_source_opt = true;
                opts->enc_dest_opt = false;
            } else if (strncmp(valstr, "dest", 4) == 0) {
                opts->enc_source_opt = false;
                opts->enc_dest_opt = true;
            } else if (strncmp(valstr, "neither", 7) == 0 ||
                    strncmp(valstr, "none", 4) == 0) {
                opts->enc_source_opt = false;
                opts->enc_dest_opt = false;
            } else {
                fprintf(stderr, "Unexpected value for 'encode_addresses' option: %s\n", valstr);
                fprintf(stderr, "Should be one of ('both', 'neither', 'source', 'dest')\n");
                return -1;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "prefix_replace")
                        == 0) {

            if (opts->enc_key) {
                fprintf(stderr, "Error: multiple IP anonymisation methods are configured, please reduce to one.\n");
                return -1;
            }

            opts->enc_type = ENC_PREFIX_SUBSTITUTION;
            opts->enc_key = strdup((char *)value->data.scalar.value);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "cryptopan_key")
                        == 0) {

            if (opts->enc_key) {
                fprintf(stderr, "Error: multiple IP anonymisation methods are configured, please reduce to one.\n");
                return -1;
            }

            opts->enc_type = ENC_CRYPTOPAN;
            opts->enc_key = strdup((char *)value->data.scalar.value);
        }
    }
    return 0;

}

int traceanon_yaml_parser(void *arg, yaml_document_t *doc,
        yaml_node_t *key, yaml_node_t *value) {

    traceanon_opts_t *opts = (traceanon_opts_t *)arg;

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_MAPPING_NODE
            && strcmp((char *)key->data.scalar.value, "ipanon") == 0) {

        if (parse_anonip_section(opts, doc, value) < 0) {
            return -1;
        }

    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_MAPPING_NODE
            && strcmp((char *)key->data.scalar.value, "radius") == 0) {

        if (parse_radius_section(opts, doc, value) < 0) {
            return -1;
        }

    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "compress_level") == 0) {
        opts->level = strtoul((char *)value->data.scalar.value, NULL, 0);
        if (opts->level > 9) {
            fprintf(stderr, "traceanon cannot set a compression level > 9\n");
            opts->level = 9;
        }
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "compress_type") == 0) {
        opts->compress_type = yaml_compress_type(
                (char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "threads") == 0) {
        opts->threads = strtoul((char *)value->data.scalar.value, NULL, 0);
        if (opts->threads == 0) {
            fprintf(stderr, "traceanon must have at least one processing thread!\n");
            opts->threads = 1;
        }
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "filterstring") == 0) {
        opts->filterstring = strdup((char *)value->data.scalar.value);
    }

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
