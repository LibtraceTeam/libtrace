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
#include "config.h"
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>

/* This file contains the implementation of the libtrace IO API, which format
 * modules should use to open, read from, write to, seek and close trace files.
 */

struct compression_type compression_type[]  = {
	{ "GZ",		"gz", 	WANDIO_COMPRESS_ZLIB 	},
	{ "BZ2",	"bz2", 	WANDIO_COMPRESS_BZ2	},
	{ "NONE",	"",	WANDIO_COMPRESS_NONE	}
};

int keep_stats = 0;
int force_directio_write = 0;
int force_directio_read = 0;
int use_threads = 1;

uint64_t read_waits = 0;
uint64_t write_waits = 0;

static void do_option(const char *option)
{
	if (*option == '\0') 
		;
	else if (strcmp(option,"stats") == 0)
		keep_stats = 1;
	else if (strcmp(option,"directwrite") == 0)
		force_directio_write = 1;
	else if (strcmp(option,"directread") == 0)
		force_directio_read  = 1;
	else if (strcmp(option,"nothreads") == 0)
		use_threads = 0;
	else {
		fprintf(stderr,"Unknown libtraceio debug option '%s'\n", option);
	}
}

static void parse_env(void)
{
	const char *str = getenv("LIBTRACEIO");
	char option[1024];
	const char *ip;
	char *op;

	if (!str)
		return;

	for(ip=str, op=option; *ip!='\0' && op < option+sizeof(option); ++ip) {
		if (*ip == ',') {
			*op='\0';
			do_option(option);
			op=option;
		}
		else
			*(op++) = *ip;
	}
	*op='\0';
	do_option(option);
}


#define READ_TRACE 0
#define WRITE_TRACE 0

io_t *wandio_create(const char *filename)
{
	parse_env();

	/* Use a peeking reader to look at the start of the trace file and
	 * determine what type of compression may have been used to write
	 * the file */
	io_t *io = peek_open(stdio_open(filename));
	char buffer[1024];
	int len;
	if (!io)
		return NULL;
	len = wandio_peek(io, buffer, sizeof(buffer));
#if HAVE_LIBZ
	/* Auto detect gzip compressed data */
	if (len>=2 && buffer[0] == '\037' && buffer[1] == '\213') { 
		io = zlib_open(io);
	}
	/* Auto detect compress(1) compressed data (gzip can read this) */
	if (len>=2 && buffer[0] == '\037' && buffer[1] == '\235') {
		io = zlib_open(io);
	}
#endif
#if HAVE_LIBBZ2
	/* Auto detect bzip compressed data */
	if (len>=3 && buffer[0] == 'B' && buffer[1] == 'Z' && buffer[2] == 'h') { 
		io = bz_open(io);
	}
#endif
	
	/* Now open a threaded, peekable reader using the appropriate module
	 * to read the data */

	if (use_threads)
		io = thread_open(io);
	
	return peek_open(io);
}

off_t wandio_tell(io_t *io)
{
	if (!io->source->tell) {
		errno = -ENOSYS;
		return -1;
	}
	return io->source->tell(io);
}

off_t wandio_seek(io_t *io, off_t offset, int whence)
{
	if (!io->source->seek) {
		errno = -ENOSYS;
		return -1;
	}
	return io->source->seek(io,offset,whence);
}

off_t wandio_read(io_t *io, void *buffer, off_t len)
{ 
	off_t ret;
#if READ_TRACE
	fprintf(stderr,"read(%s): %d bytes\n",io->source->name, (int)len);
#endif
	ret=io->source->read(io,buffer,len); 
	return ret;
}

off_t wandio_peek(io_t *io, void *buffer, off_t len)
{
	off_t ret;
	assert(io->source->peek); /* If this fails, it means you're calling
				   * peek on something that doesn't support
				   * peeking.   Push a peek_open() on the io
				   * first.
				   */
	ret=io->source->peek(io, buffer, len);
	return ret;
}

void wandio_destroy(io_t *io)
{ 
	if (keep_stats) 
		fprintf(stderr,"LIBTRACEIO STATS: %"PRIu64" blocks on read\n", read_waits);
	io->source->close(io); 
}

iow_t *wandio_wcreate(const char *filename, int compression_level, int flags)
{
	iow_t *iow;

	assert ( compression_level >= 0 && compression_level <= 9 );

	iow=stdio_wopen(filename);

	/* We prefer zlib if available, otherwise we'll use bzip. If neither
	 * are present, guess we'll just have to write uncompressed */
#if HAVE_LIBZ
	if (compression_level != 0 && 
	    (flags & WANDIO_COMPRESS_MASK) == WANDIO_COMPRESS_ZLIB) {
		iow = zlib_wopen(iow,compression_level);
	}
#endif
#if HAVE_LIBBZ2
	else if (compression_level != 0 && 
	    (flags & WANDIO_COMPRESS_MASK) == WANDIO_COMPRESS_BZ2) {
		iow = bz_wopen(iow,compression_level);
	}
#endif
	/* Open a threaded writer */
	if (use_threads)
		return thread_wopen(iow);
	else
		return iow;
}

off_t wandio_wwrite(iow_t *iow, const void *buffer, off_t len)
{
#if WRITE_TRACE
	fprintf(stderr,"wwrite(%s): %d bytes\n",iow->source->name, (int)len);
#endif
	return iow->source->write(iow,buffer,len);	
}

void wandio_wdestroy(iow_t *iow)
{
	iow->source->close(iow);
	if (keep_stats) 
		fprintf(stderr,"LIBTRACEIO STATS: %"PRIu64" blocks on write\n", write_waits);
}

