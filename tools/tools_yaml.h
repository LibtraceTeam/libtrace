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

#ifndef LIBTRACE_TOOLS_YAML_H_
#define LIBTRACE_TOOLS_YAML_H_

#include <yaml.h>
#include <libtrace.h>

#ifdef __cplusplus 
extern "C" {
#endif

int yaml_parser(char *configfile, void *arg,
        int (*parse_mapping)(void *, yaml_document_t *, yaml_node_t *,
            yaml_node_t *));
int yaml_parse_onoff(char *value);
trace_option_compresstype_t yaml_compress_type(char *compress_type_str);

#ifdef __cplusplus
}
#endif
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
