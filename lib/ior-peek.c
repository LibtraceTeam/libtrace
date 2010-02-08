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
 * $Id: format_erf.c 1517 2010-02-08 01:11:04Z salcock $
 *
 */

#include "wandio.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/* Libtrace IO module implementing a peeking reader.
 *
 * Assuming my understanding of Perry's code is correct, this module provides
 * generic support for "peeking" that can be used in concert with any other
 * implemented IO reader. 
 *
 * The other IO reader is a "child" to the peeking reader and is used to read
 * the data into a buffer managed by the peeking reader. Any actual "peeks"
 * are serviced from the managed buffer, which means that we do not have to
 * manipulate the read offsets directly in zlib or bzip, for instance.
 */

struct peek_t {
	io_t *child;
	char *buffer;
	int length;
	int offset;
};

extern io_source_t peek_source;

#define DATA(io) ((struct peek_t *)((io)->data))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

io_t *peek_open(io_t *child)
{
	io_t *io;
	if (!child)
		return NULL;
	io =  malloc(sizeof(io_t));
	io->data = malloc(sizeof(struct peek_t));
	io->source = &peek_source;

	/* Wrap the peeking reader around the "child" */
	DATA(io)->child = child;
	DATA(io)->buffer = NULL;
	DATA(io)->length = 0;
	DATA(io)->offset = 0;	

	return io;
}

static off_t peek_read(io_t *io, void *buffer, off_t len)
{
	off_t ret = 0;

	/* Is some of this data in the buffer? */
	if (DATA(io)->buffer) {
		ret = MIN(len,DATA(io)->length - DATA(io)->offset);

		/* Copy everything we've got into their buffer, and shift our
		 * offset so that we don't peek at the data we've read again */
		memcpy(buffer, 
			DATA(io)->buffer + DATA(io)->offset,
			ret);
		buffer += ret;
		DATA(io)->offset += ret;
		len -= ret;
	}
	/* Use the child reader to get the rest of the required data */
	if (len>0) {
		off_t bytes_read = 
			DATA(io)->child->source->read(
				DATA(io)->child, buffer, len);
		/* Error? */
		if (bytes_read < 1) {
			/* Return if we have managed to get some data ok */
			if (ret > 0)
				return ret;
			/* Return the error upstream */
			return bytes_read;
		}
		ret += bytes_read;
	}

	/* Have we read past the end of the buffer? */
	if (DATA(io)->buffer && DATA(io)->offset >= DATA(io)->length) {
		/* If so, free the memory it used */
		free(DATA(io)->buffer);
		DATA(io)->buffer = NULL;
		DATA(io)->offset = 0;
		DATA(io)->length = 0;
	}

	return ret;
}

/* Round reads for peeks into the buffer up to this size */
#define PEEK_SIZE (1024*1024)

static off_t peek_peek(io_t *io, void *buffer, off_t len)
{
	off_t ret = 0;

	/* Is there enough data in the buffer to serve this request? */
	if (DATA(io)->length - DATA(io)->offset < len) {
		/* No, we need to extend the buffer. */
		off_t read_amount = len - (DATA(io)->length - DATA(io)->offset);
		/* Round the read_amount up to the nearest MB */
		read_amount += PEEK_SIZE - ((DATA(io)->length + read_amount) % PEEK_SIZE);
		DATA(io)->buffer = realloc(DATA(io)->buffer, DATA(io)->length + read_amount);
		/* Use the child reader to read more data into our managed
		 * buffer */
		read_amount = wandio_read(DATA(io)->child, 
			DATA(io)->buffer + DATA(io)->length,
			read_amount);

		/* Pass errors up */
		if (read_amount <1) {
			return read_amount;
		}

		DATA(io)->length += read_amount;
	}

	/* Right, now return data from the buffer (that now should be large 
	 * enough, but might not be if we hit EOF) */
	ret = MIN(len, DATA(io)->length - DATA(io)->offset);
	memcpy(buffer, DATA(io)->buffer + DATA(io)->offset, ret);
	return ret;
}

static off_t peek_tell(io_t *io)
{
	/* We don't actually maintain a read offset as such, so we want to
	 * return the child's read offset */
	return wandio_tell(DATA(io)->child);
}

static off_t peek_seek(io_t *io, off_t offset, int whence)
{
	/* Again, we don't have a genuine read offset so we need to pass this
	 * one on to the child */
	return wandio_seek(DATA(io)->child,offset,whence);
}

static void peek_close(io_t *io)
{
	/* Make sure we close the child that is doing the actual reading! */
	wandio_destroy(DATA(io)->child);
	if (DATA(io)->buffer)
		free(DATA(io)->buffer);
	free(io->data);
	free(io);
}

io_source_t peek_source = {
	"peek",
	peek_read,
	peek_peek,
	peek_tell,
	peek_seek,
	peek_close
};

