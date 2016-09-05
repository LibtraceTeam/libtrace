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

static void output_html_init(struct output_data_t *out)
{
	int i;
	printf("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n");
	printf("<html>\n");
	printf("<head>\n");
	printf(" <title>%s</title>\n",out->title);
	printf(" <style type=\"text/css\">\n");
	printf("  table         { border-collapse: collapse; width: 100%%}\n");
	printf("  td            { border: thin black solid; }\n");
	printf("  .numeric      { text-align: right; }\n");
	printf("  .even         { background: #e0e0e0; }\n");
	printf("  .odd          { background: #ffffff; }\n");
	printf("  .rowheading   { text-align: right; }\n");
	printf(" </style>\n");
	printf("</head>\n");
	printf("<body>\n");
	printf("<h1>%s</h1>\n",out->title);
	printf("<table>\n");
	printf(" <tr>\n");
	for(i=0;i<out->columns;++i) {
		printf("  <th>%s</th>",out->labels[i]);
	}
	printf(" </tr>\n");
	out->private_format_data=malloc(sizeof(int));
	*(int*)out->private_format_data=0;
}

static void output_html_flush(struct output_data_t *out)
{
	int i;
	printf(" <tr class=\"%s\">\n",((*(int*)out->private_format_data)++)&1?"odd":"even");
	for(i=0;i<out->columns;++i) {
		switch (out->data[i].type) {
			case TYPE_int: 
				printf("  <td class=\"numeric\">%" PRIu64 "</td>\n",out->data[i].d.d_int);
				break;
			case TYPE_str:
				printf("  <td>%s</td>\n",out->data[i].d.d_str);
				free(out->data[i].d.d_str);
				break;
			case TYPE_float:
				printf("  <td class=\"numeric\">%f</td>\n",out->data[i].d.d_float);
				break;
			case TYPE_time:
				printf("  <td class=\"numeric\">%.03f</td>\n",out->data[i].d.d_time);
				break;
		}
	}
	printf(" </tr>\n");
}

static void output_html_destroy(struct output_data_t *out)
{
	(void)out;
	printf("</table>\n");
	printf("</body>\n");
	printf("</html>\n");
}

struct output_type_t output_html = {
.name= "html",
.init= output_html_init,
.flush= output_html_flush,
.destroy= output_html_destroy,
};
