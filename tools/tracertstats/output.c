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

#include "config.h"
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "output.h"

struct output_type_t *output_formats[] = {
	&output_txt,
	&output_csv,
	&output_html,
#ifdef HAVE_LIBGDC
	&output_png,
#endif
	NULL
};

struct output_data_t *output_init(char *title,char *type)
{
	output_data_t *data = malloc(sizeof(output_data_t));
	int i=0;
	data->title=strdup(title);
	data->labels=NULL;
	data->columns=0;
	data->data=NULL;
	while(output_formats[i]) {
		if (strcmp(output_formats[i]->name,type)==0) {
			data->format = output_formats[i];
			return data;
		}
		++i;
	}
	/* Not found */
	free(data->title);
	free(data);
	return NULL;
}

void output_add_column(struct output_data_t *out,char *col)
{
	++out->columns;
	out->labels=realloc(out->labels,out->columns*sizeof(char *));
	out->labels[out->columns-1]=strdup(col);
	out->data=realloc(out->data,out->columns*sizeof(struct data_t));
}

void output_flush_headings(struct output_data_t *out)
{
	out->format->init(out);
}

#define output_set_data(type_) \
	void output_set_data_ ## type_(struct output_data_t *out,	\
			int col,TYPE__ ## type_ data)\
	{	\
		assert(col>=0 && col<out->columns); \
		out->data[col].type=TYPE_ ## type_; \
		out->data[col].d.d_ ## type_ = data; \
	}

output_set_data(str)
output_set_data(int)
output_set_data(float)
output_set_data(time)
#undef output_set_data

void output_flush_row(struct output_data_t *out)
{
	out->format->flush(out);
}

void output_destroy(struct output_data_t *out)
{
	int i;
	out->format->destroy(out);
	for(i=0;i<out->columns;++i) {
		free(out->labels[i]);
	}
	free(out->data);
	free(out->labels);
	free(out->title);
	free(out);
}

