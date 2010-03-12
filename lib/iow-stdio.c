/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Daniel Lawson 
 *          Perry Lorier
 *          Shane Alcock 
 *          
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libtrace; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 *
 */


#define _GNU_SOURCE 1
#include "wandio.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/* Libtrace IO module implementing a standard IO writer, i.e. no decompression
 */

struct stdiow_t {
	int fd;
};

extern iow_source_t stdio_wsource;

#define DATA(iow) ((struct stdiow_t *)((iow)->data))

iow_t *stdio_wopen(const char *filename)
{
	iow_t *iow = malloc(sizeof(iow_t));
	iow->source = &stdio_wsource;
	iow->data = malloc(sizeof(struct stdiow_t));

	if (strcmp(filename,"-") == 0) 
		DATA(iow)->fd = 1; /* STDOUT */
	else
		DATA(iow)->fd = open(filename,
				O_WRONLY
				|O_CREAT
				|O_TRUNC
				|(force_directio_write?O_DIRECT:0),
				0666);

	if (DATA(iow)->fd == -1) {
		free(iow);
		return NULL;
	}

	return iow;
}

static off_t stdio_wwrite(iow_t *iow, const char *buffer, off_t len)
{
	return write(DATA(iow)->fd,buffer,len);
}

static void stdio_wclose(iow_t *iow)
{
	close(DATA(iow)->fd);
	free(iow->data);
	free(iow);
}

iow_source_t stdio_wsource = {
	"stdiow",
	stdio_wwrite,
	stdio_wclose
};
