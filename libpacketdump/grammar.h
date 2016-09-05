/*
 *
 * Copyright (c) 2007-2016 The University of Waikato, Hamilton, New Zealand.
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
#ifndef _PARSER_H
#define _PARSER_H

#include <inttypes.h>

enum node_type_t {
    NEXTHEADER,
    FIELD
};

enum byte_order_t {
    BIGENDIAN,
    LITTLEENDIAN
}; 

enum display_t {
    DISPLAY_NONE,
    DISPLAY_HEX,
    DISPLAY_INT,
    DISPLAY_IPV4,
    DISPLAY_MAC,
    DISPLAY_FLAG
};

/* This is more complicated that I feel it needs to be... */

typedef struct next {
    char *prefix;		    /* search prefix for nextheader file */
    char *fieldname;		    /* name of the field whose value we use */
    struct field *target;	    /* link to the field whose value we use */
} next_t;
    
typedef struct field {
    enum byte_order_t order;	    /* byte order of field */
    uint16_t size;		    /* size of the field in bits */
    enum display_t display;	    /* how the data should be displayed */
    char *identifier;		    /* display prefix + field identifier */
    uint64_t value;		    /* calculated value for this field */
} field_t; 

typedef union node {
    field_t *field;
    next_t *nextheader;
} node_t;

typedef struct element {
    enum node_type_t type;
    struct element *next;
    node_t *data;
} element_t;
    
element_t *parse_protocol_file(char *filename);
void decode_protocol_file(uint16_t link_type,const char *packet,int len, element_t* el);

typedef uint64_t bitbuffer_t;
#endif
