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

#ifndef OUTPUT_H
#define OUTPUT_H
#include <inttypes.h>

typedef char *TYPE__str;
typedef uint64_t TYPE__int;
typedef double TYPE__float;
typedef double TYPE__time;
struct data_t {
    enum { TYPE_str, TYPE_int, TYPE_float, TYPE_time } type;
    union {
        TYPE__str d_str;
        TYPE__int d_int;
        TYPE__float d_float;
        TYPE__time d_time;
    } d;
};

typedef struct output_data_t {
    char *title;
    int columns;
    char **labels;
    struct data_t *data;
    struct output_type_t *format;
    void *private_format_data;
} output_data_t;

struct output_type_t {
    char *name;
    void (*init)(struct output_data_t *);
    void (*flush)(struct output_data_t *);
    void (*destroy)(struct output_data_t *);
};
extern struct output_type_t output_txt;
extern struct output_type_t output_csv;
extern struct output_type_t output_html;
extern struct output_type_t output_png;

struct output_data_t *output_init(char *title, char *format);
void output_add_column(struct output_data_t *out, char *col);
void output_flush_headings(struct output_data_t *out);
void output_set_data_int(struct output_data_t *out, int col, uint64_t data);
void output_set_data_str(struct output_data_t *out, int col, char *data);
void output_set_data_float(struct output_data_t *out, int col, double data);
void output_set_data_time(struct output_data_t *out, int col, double data);
void output_flush_row(struct output_data_t *out);
void output_destroy(struct output_data_t *out);

#endif
