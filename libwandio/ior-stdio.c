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
#include "wandio_internal.h"
#include "wandio.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/* Libtrace IO module implementing a standard IO reader, i.e. no decompression
 */

struct stdio_t {
	int fd;
};

extern io_source_t stdio_source;

#define DATA(io) ((struct stdio_t *)((io)->data))

io_t *stdio_open(const char *filename)
{
	io_t *io = malloc(sizeof(io_t));
	io->data = malloc(sizeof(struct stdio_t));

	if (strcmp(filename,"-") == 0)
		DATA(io)->fd = 0; /* STDIN */
	else
		DATA(io)->fd = open(filename,
			O_RDONLY
#ifdef O_DIRECT
			|(force_directio_read?O_DIRECT:0)
#endif
			);
	io->source = &stdio_source;

	if (DATA(io)->fd == -1) {
		free(io);
		return NULL;
	}

	return io;
}

static off_t stdio_read(io_t *io, void *buffer, off_t len)
{
	return read(DATA(io)->fd,buffer,len);
}

static off_t stdio_tell(io_t *io)
{
	return lseek(DATA(io)->fd, 0, SEEK_CUR);
}

static off_t stdio_seek(io_t *io, off_t offset, int whence)
{
	return lseek(DATA(io)->fd, offset, whence);
}

static void stdio_close(io_t *io)
{
	close(DATA(io)->fd);
	free(io->data);
	free(io);
}

io_source_t stdio_source = {
	"stdio",
	stdio_read,
	NULL,
	stdio_tell,
	stdio_seek,
	stdio_close
};

