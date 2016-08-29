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


#include "output.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <string.h>

#define COLWIDTH 11

static void output_txt_init(struct output_data_t *out)
{
	int i;
	for(i=0;i<out->columns;++i) {
		if (strlen(out->labels[i])>8)
			printf("[%i]: %s\n",i,out->labels[i]);
	}
	printf("\n");
	for(i=0;i<out->columns;++i) {
		if (strlen(out->labels[i])>8)
			printf("[%*i] ",COLWIDTH-3,i);
		else
			printf("%*s ",COLWIDTH-1,out->labels[i]);
	}
	printf("\n");
}

static void output_txt_flush(struct output_data_t *out)
{
	int i;
	for(i=0;i<out->columns;++i) {
		switch (out->data[i].type) {
			case TYPE_int: 
				printf("%*" PRIu64 " ",COLWIDTH-1,out->data[i].d.d_int);
				break;
			case TYPE_str:
				printf("%*s ",COLWIDTH-1,out->data[i].d.d_str);
				free(out->data[i].d.d_str);
				break;
			case TYPE_float:
				printf("%*f ",COLWIDTH-1,out->data[i].d.d_float);
				break;
			case TYPE_time:
				printf("%*.0f ",COLWIDTH-1,out->data[i].d.d_time);
				break;
		}
	}
	printf("\n");
}

static void output_txt_destroy(struct output_data_t *out)
{
	(void)out;
	/* Do nothing */
}

struct output_type_t output_txt = {
.name= "txt",
.init= output_txt_init,
.flush= output_txt_flush,
.destroy= output_txt_destroy,
};
