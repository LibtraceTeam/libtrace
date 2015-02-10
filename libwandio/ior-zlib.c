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
#include <zlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Libtrace IO module implementing a zlib reader */

enum err_t {
	ERR_OK	= 1,
	ERR_EOF = 0,
	ERR_ERROR = -1
};

struct zlib_t {
	Bytef inbuff[1024*1024]; /* bytef is what zlib uses for buffer pointers */
	z_stream strm;
	io_t *parent;
	int outoffset;
	enum err_t err;
        size_t sincelastend;
};


extern io_source_t zlib_source; 

#define DATA(io) ((struct zlib_t *)((io)->data))
#define min(a,b) ((a)<(b) ? (a) : (b))

io_t *zlib_open(io_t *parent)
{
	io_t *io;
	if (!parent)
		return NULL;
	io = malloc(sizeof(io_t));
	io->source = &zlib_source;
	io->data = malloc(sizeof(struct zlib_t));

	DATA(io)->parent = parent;

	DATA(io)->strm.next_in = NULL;
	DATA(io)->strm.avail_in = 0;
	DATA(io)->strm.next_out = NULL;
	DATA(io)->strm.avail_out = 0;
	DATA(io)->strm.zalloc = Z_NULL;
	DATA(io)->strm.zfree = Z_NULL;
	DATA(io)->strm.opaque = NULL;
	DATA(io)->err = ERR_OK;
        DATA(io)->sincelastend = 1;

	inflateInit2(&DATA(io)->strm, 15 | 32);

	return io;
}


static off_t zlib_read(io_t *io, void *buffer, off_t len)
{
	if (DATA(io)->err == ERR_EOF)
		return 0; /* EOF */
	if (DATA(io)->err == ERR_ERROR) {
		errno=EIO;
		return -1; /* ERROR! */
	}

	DATA(io)->strm.avail_out = len;
	DATA(io)->strm.next_out = (Bytef*)buffer;

	while (DATA(io)->err == ERR_OK && DATA(io)->strm.avail_out > 0) {
		while (DATA(io)->strm.avail_in <= 0) {
			int bytes_read = wandio_read(DATA(io)->parent, 
				(char*)DATA(io)->inbuff,
				sizeof(DATA(io)->inbuff));
			if (bytes_read == 0) {
                                /* If we get EOF immediately after a 
                                 * Z_STREAM_END, then we assume we've reached 
                                 * the end of the file. If there was data 
                                 * between the Z_STREAM_END and the EOF, the
                                 * file has more likely been truncated.
                                 */
                                if (DATA(io)->sincelastend > 0) {
                                        fprintf(stderr, "Unexpected EOF while reading compressed file -- file is probably incomplete\n");
                                        errno = EIO;
                                        DATA(io)->err = ERR_ERROR;
                                        return -1;
                                }

                                /* EOF */
				if (DATA(io)->strm.avail_out == (uint32_t)len) {
                                        DATA(io)->err = ERR_EOF;
					return 0;
				}
				/* Return how much data we've managed to read so far. */
				return len-DATA(io)->strm.avail_out;
			}
			if (bytes_read < 0) { /* Error */
				/* errno should be set */
				DATA(io)->err = ERR_ERROR;
				/* Return how much data we managed to read ok */
				if (DATA(io)->strm.avail_out != (uint32_t)len) {
					return len-DATA(io)->strm.avail_out;
				}
				/* Now return error */
				return -1;
			}
			DATA(io)->strm.next_in = DATA(io)->inbuff;
			DATA(io)->strm.avail_in = bytes_read;
                        DATA(io)->sincelastend += bytes_read;
		}
		/* Decompress some data into the output buffer */
		int err=inflate(&DATA(io)->strm, 0);
		switch(err) {
			case Z_OK:
				DATA(io)->err = ERR_OK;
				break;
			case Z_STREAM_END:
				/* You would think that an "EOF" on the stream would mean we'd
 				 * want to pass on an EOF?  Nope.  Some tools (*cough* corel *cough*)
 				 * annoyingly close and reopen the gzip stream leaving Z_STREAM_END
 				 * mines for us to find.
 				 */
				inflateEnd(&DATA(io)->strm);
				inflateInit2(&DATA(io)->strm, 15 | 32);
				DATA(io)->err = ERR_OK;
                                DATA(io)->sincelastend = 0;
				break;
			default:
				errno=EIO;
				DATA(io)->err = ERR_ERROR;
		}
	}
	/* Return the number of bytes decompressed */
	return len-DATA(io)->strm.avail_out;
}

static void zlib_close(io_t *io)
{
	inflateEnd(&DATA(io)->strm);
	wandio_destroy(DATA(io)->parent);
	free(io->data);
	free(io);
}

io_source_t zlib_source = {
	"zlib",
	zlib_read,
	NULL,	/* peek */
	NULL,	/* tell */
	NULL,	/* seek */
	zlib_close
};

