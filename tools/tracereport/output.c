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


#define _GNU_SOURCE
#include <stdio.h>
#include <inttypes.h>
#include <lt_inttypes.h>


enum stats_output_format_t {
	CSV, TXT, HTML, XML, ODOC
};
struct stats_output_t {
	enum stats_output_format_t type;
};

struct stats_output_t *create_stats(enum stats_output_format_t format)
{
	struct stats_output_t *output=malloc(sizeof(struct stats_output_t));
	output->type=format;
	switch (type) {
		case CSV:
			break;
		case HTML:
			printf("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n");
			printf("<html>\n");
			printf("<head>\n");
			printf(" <title>Report</title>\n");
			printf(" <style>\n");
			printf("  .table 	{ border-collapse: collapse; }\n");
			printf("  td		{ border: thin black solid; }\n");
			printf("  .numeric	{ text-align: right; }\n");
			printf("  .even		{ background: #a0e0e0; }\n");
			printf("  .odd		{ background: #ffffff; }\n");
			printf("  .rowheading	{ text-align: right; }\n");
			printf(" </style>\n");
			printf("</head>\n");
			printf("<body>\n");
			printf("<h1>Report</h1>\n");
			printf("<table>\n");
			printf(" <tr>\n");
			break;
		case XML:
			printf("<?xml version=\"1.0\" charset=\"utf-8\"?>\n");
			printf("<results>\n");
			printf(" <columnheadings>\n");
			break;
		default:
			fprintf(stderr,"Unknown format\n");
			break;
	}
	return output;
}

struct stats_output_t *add_column_heading(struct stats_output_t *out,char *heading,...)
{
	va_list va;
	va_start(va,heading);
	vasprintf(&buf,heading,va);
	switch (out->type) {
		case CSV:
	}
	va_end(va);
}
