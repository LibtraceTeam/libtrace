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

#include "wandio.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>

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

/* for O_DIRECT we have to read in multiples of this */
#define MIN_READ_SIZE 4096
/* Round reads for peeks into the buffer up to this size */
#define PEEK_SIZE (1024*1024)

struct peek_t {
	io_t *child;
	char *buffer;
	off_t length; /* Length of buffer */
	off_t offset; /* Offset into buffer */
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

/* Read at least "len" bytes from the child io into the internal buffer, and return how many
   bytes was actually read.
 */
static off_t refill_buffer(io_t *io, off_t len)
{
	off_t bytes_read;
	assert(DATA(io)->length - DATA(io)->offset == 0);
	/* Select the largest of "len", PEEK_SIZE and the current peek buffer size
	 * and then round up to the nearest multiple of MIN_READ_SIZE 
	 */
	bytes_read = len < PEEK_SIZE ? PEEK_SIZE : len;
	bytes_read = bytes_read < DATA(io)->length ? DATA(io)->length : bytes_read;
	bytes_read += MIN_READ_SIZE - (bytes_read % MIN_READ_SIZE);
	/* Is the current buffer big enough? */
	if (DATA(io)->length < bytes_read) {
		int res = 0;
		void *buf_ptr = (void *)(DATA(io)->buffer);

		if (buf_ptr)
			free(buf_ptr);
		DATA(io)->length = bytes_read;
		DATA(io)->offset = 0;
#if _POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600
		/* We need to do this as read() of O_DIRECT might happen into 
		 * this buffer.  The docs suggest 512 bytes is all we need to 
		 * align to, but I'm suspicious. I expect disks with 4k blocks 
		 * will arrive soon, and thus 4k is the minimum I'm willing to 
		 * live with.
		 */
		res = posix_memalign(&buf_ptr, 4096, DATA(io)->length);
		if (res != 0) {
			fprintf(stderr, "Error aligning IO buffer: %d\n",
					res);
			return res;
		}
		DATA(io)->buffer = buf_ptr;
#else
		res = 0;	/* << Silly warning */ 
		DATA(io)->buffer = malloc(DATA(io)->length);
#endif
	}
	else
		DATA(io)->length = bytes_read;

	assert(DATA(io)->buffer);

	/* Now actually attempt to read that many bytes */
	bytes_read = DATA(io)->child->source->read(	
			DATA(io)->child, DATA(io)->buffer, bytes_read);

	DATA(io)->offset = 0;
	DATA(io)->length = bytes_read;
	
	/* Error? */
	if (bytes_read < 1)
		return bytes_read;

	return bytes_read;
	
}

static off_t peek_read(io_t *io, void *buffer, off_t len)
{
	off_t ret = 0;

	/* Is some of this data in the buffer? */
	if (DATA(io)->buffer) {
		ret = MIN(len,DATA(io)->length - DATA(io)->offset);

		/* Copy anything we've got into their buffer, and shift our
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
		/* To get here, the buffer must be empty */
		assert(DATA(io)->length-DATA(io)->offset == 0);
		off_t bytes_read;
		/* If they're reading exactly a block size, just use that, no point in malloc'ing 
		 * and memcpy()ing needlessly.  However, if the buffer isn't aligned, we need to
		 * pass on an aligning buffer, skip this and do it into our own aligned buffer.
		 */
		if ((len % MIN_READ_SIZE  == 0) && ((ptrdiff_t)buffer % 4096)==0) {
			assert(((ptrdiff_t)buffer % 4096) == 0);
			bytes_read = DATA(io)->child->source->read(
					DATA(io)->child, buffer, len);
			/* Error? */
			if (bytes_read < 1) {
				/* Return if we have managed to get some data ok */
				if (ret > 0)
					return ret;
				/* Return the error upstream */
				return bytes_read;
			}
		}
		else {
			bytes_read = refill_buffer(io, len);
			if (bytes_read < 1) {
				/* Return if we have managed to get some data ok */
				if (ret > 0)
					return ret;
				/* Return the error upstream */
				return bytes_read;
			}
			/* Now grab the number of bytes asked for. */
			len = len < bytes_read ? len : bytes_read;
			memcpy(buffer, DATA(io)->buffer, len);

			DATA(io)->offset = len;
			bytes_read = len;
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

static void *alignedrealloc(void *old, size_t oldsize, size_t size, int *res)
{
#if _POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600
	void *new;
	/* Shortcut resizing */
	if (size < oldsize)
		return old;
	*res = posix_memalign(&new, 4096, size);
	if (*res != 0) {
		fprintf(stderr, "Error aligning IO buffer: %d\n", *res);
		
		return NULL;
	}
	assert(oldsize<size);
	memcpy(new,old,oldsize);
	free(old);
	return new;
#else
	/* These no-ops are to stop the compiler whinging about unused
	 * parameters */
	(void)oldsize;
	(void)res;
	return realloc(old,size);
#endif
}


static off_t peek_peek(io_t *io, void *buffer, off_t len)
{
	off_t ret = 0;
	int res = 0;

	/* Is there enough data in the buffer to serve this request? */
	if (DATA(io)->length - DATA(io)->offset < len) {
		/* No, we need to extend the buffer. */
		off_t read_amount = len - (DATA(io)->length - DATA(io)->offset);
		/* Round the read_amount up to the nearest MB */
		read_amount += PEEK_SIZE - ((DATA(io)->length + read_amount) % PEEK_SIZE);
		DATA(io)->buffer = alignedrealloc(DATA(io)->buffer, 
			DATA(io)->length, 
			DATA(io)->length + read_amount, &res);

		if (DATA(io)->buffer == NULL) {
			return res;	
		}

		/* Use the child reader to read more data into our managed
		 * buffer */
		read_amount = wandio_read(DATA(io)->child, 
			DATA(io)->buffer + DATA(io)->length,
			read_amount);

		/* Pass errors up */
		if (read_amount <0) {
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

