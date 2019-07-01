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

#include "config.h"

#include "tools_yaml.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <yaml.h>

int yaml_parse_onoff(char *value) {
    if (strcasecmp(value, "yes") == 0) {
        return 1;
    }

    if (strcasecmp(value, "on") == 0) {
        return 1;
    }

    if (strcasecmp(value, "true") == 0) {
        return 1;
    }

    if (strcasecmp(value, "enabled") == 0) {
        return 1;
    }

    if (strcasecmp(value, "no") == 0) {
        return 0;
    }

    if (strcasecmp(value, "off") == 0) {
        return 0;
    }

    if (strcasecmp(value, "false") == 0) {
        return 0;
    }

    if (strcasecmp(value, "disabled") == 0) {
        return 0;
    }

    return -1;
}

trace_option_compresstype_t yaml_compress_type(char *compress_type_str) {

    if (strncmp(compress_type_str, "gz", 2) == 0 ||
            strncmp(compress_type_str, "zlib", 4) == 0) {
        return TRACE_OPTION_COMPRESSTYPE_ZLIB;
    } else if (strncmp(compress_type_str, "bz", 2) == 0) {
        return TRACE_OPTION_COMPRESSTYPE_BZ2;
    } else if (strncmp(compress_type_str, "lzo", 3) == 0) {
        return TRACE_OPTION_COMPRESSTYPE_LZO;
    } else if (strncmp(compress_type_str, "zstd", 4) == 0) {
        return TRACE_OPTION_COMPRESSTYPE_ZSTD;
    } else if (strncmp(compress_type_str, "lz4", 3) == 0) {
        return TRACE_OPTION_COMPRESSTYPE_LZ4;
    } else if (strncmp(compress_type_str, "lzma", 4) == 0) {
        return TRACE_OPTION_COMPRESSTYPE_LZMA;
    } else if (strncmp(compress_type_str, "no", 2) == 0) {
        return TRACE_OPTION_COMPRESSTYPE_NONE;
    }
    fprintf(stderr, "Unknown compression type: %s\n", compress_type_str);
    return TRACE_OPTION_COMPRESSTYPE_NONE;
}

int yaml_parser(char *configfile, void *arg,
        int (*parse_mapping)(void *, yaml_document_t *, yaml_node_t *,
                yaml_node_t *)) {
    FILE *in = NULL;
    yaml_parser_t parser;
    yaml_document_t document;
    yaml_node_t *root, *key, *value;
    yaml_node_pair_t *pair;
    int ret = -1;

    if ((in = fopen(configfile, "r")) == NULL) {
        fprintf(stderr,
                "Libtrace YAML parser: failed to open config file: %s\n",
                strerror(errno));
        return -1;
    }

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, in);

    if (!yaml_parser_load(&parser, &document)) {
        fprintf(stderr, "Libtrace YAML parser: malformed config file\n");
        goto yamlfail;
    }

    root = yaml_document_get_root_node(&document);
    if (!root) {
        fprintf(stderr, "Libtrace YAML parser: config file is empty!\n");
        goto endconfig;
    }

    if (root->type != YAML_MAPPING_NODE) {
        fprintf(stderr,
                "Libtrace YAML parser: top level of config should be a map\n");
        goto endconfig;
    }
    for (pair = root->data.mapping.pairs.start;
            pair < root->data.mapping.pairs.top; pair ++) {

        key = yaml_document_get_node(&document, pair->key);
        value = yaml_document_get_node(&document, pair->value);

        if (parse_mapping(arg, &document, key, value) == -1) {
            ret = -1;
            break;
        }
        ret = 0;
    }
endconfig:
    yaml_document_delete(&document);
    yaml_parser_delete(&parser);

yamlfail:
    fclose(in);
    return ret;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
