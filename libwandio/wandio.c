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


#include "config.h"
#include "wandio_internal.h"
#include "wandio.h"
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>

/* This file contains the implementation of the libtrace IO API, which format
 * modules should use to open, read from, write to, seek and close trace files.
 */

struct wandio_compression_type compression_type[]  = {
	{ "gzip",	"gz", 	WANDIO_COMPRESS_ZLIB 	},
	{ "bzip2",      "bz2", 	WANDIO_COMPRESS_BZ2	},
	{ "lzo",	"lzo",  WANDIO_COMPRESS_LZO	},
	{ "lzma",	"xz",  WANDIO_COMPRESS_LZMA	},
	{ "NONE",	"",	WANDIO_COMPRESS_NONE	}
};

int keep_stats = 0;
int force_directio_write = 0;
int force_directio_read = 0;
int use_autodetect = 1;
unsigned int use_threads = -1;
unsigned int max_buffers = 50;

uint64_t read_waits = 0;
uint64_t write_waits = 0;

/** Parse an option.
 * stats -- Show summary stats
 * directwrite -- bypass the diskcache on write
 * directread -- bypass the diskcache on read
 * noautodetect -- disable autodetection of file compression, assume all files
 *		   are uncompressed
 * nothreads -- Don't use threads
 * threads=n -- Use a maximum of 'n' threads for thread farms
 */
static void do_option(const char *option)
{
	if (*option == '\0') 
		;
	else if (strcmp(option,"stats") == 0)
		keep_stats = 1;
	/*
	else if (strcmp(option,"directwrite") == 0)
		force_directio_write = 1;
	else if (strcmp(option,"directread") == 0)
		force_directio_read  = 1;
	*/
	else if (strcmp(option,"nothreads") == 0)
		use_threads = 0;
	else if (strcmp(option,"noautodetect") == 0)
		use_autodetect = 0;
	else if (strncmp(option,"threads=",8) == 0)
		use_threads = atoi(option+8);
	else if (strncmp(option,"buffers=",8) == 0)
		max_buffers = atoi(option+8);
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
#define PIPELINE_TRACE 0

#if PIPELINE_TRACE
#define DEBUG_PIPELINE(x) fprintf(stderr,"PIPELINE: %s\n",x)
#else
#define DEBUG_PIPELINE(x) 
#endif

static io_t *create_io_reader(const char *filename, int autodetect)
{

	/* Use a peeking reader to look at the start of the trace file and
	 * determine what type of compression may have been used to write
	 * the file */

	DEBUG_PIPELINE("stdio");
	DEBUG_PIPELINE("peek");
	io_t *io = peek_open(stdio_open(filename));
	unsigned char buffer[1024];
	int len;
	if (!io)
		return NULL;
	len = wandio_peek(io, buffer, sizeof(buffer));
	/* Auto detect gzip compressed data -- if autodetect is false,
	 * instead we just assume uncompressed.
	 */

	if (autodetect) {
		if (len>=3 && buffer[0] == 0x1f && buffer[1] == 0x8b &&
				buffer[2] == 0x08) { 
#if HAVE_LIBZ
			DEBUG_PIPELINE("zlib");
			io = zlib_open(io);
#else
			fprintf(stderr, "File %s is gzip compressed but libtrace has not been built with zlib support!\n", filename);
			return NULL;
#endif
		}
		/* Auto detect compress(1) compressed data (gzip can read this) */
		if (len>=2 && buffer[0] == 0x1f && buffer[1] == 0x9d) {
#if HAVE_LIBZ
			DEBUG_PIPELINE("zlib");
			io = zlib_open(io);
#else
			fprintf(stderr, "File %s is compress(1) compressed but libtrace has not been built with zlib support!\n", filename);
			return NULL;
#endif
		}

		/* Auto detect bzip compressed data */
		if (len>=3 && buffer[0] == 'B' && buffer[1] == 'Z' && buffer[2] == 'h') { 
#if HAVE_LIBBZ2
			DEBUG_PIPELINE("bzip");
			io = bz_open(io);
#else
			fprintf(stderr, "File %s is bzip compressed but libtrace has not been built with bzip2 support!\n", filename);
			return NULL;
#endif
		}

                if (len >=5 && buffer[0] == 0xfd && buffer[1] == '7' && 
                                buffer[2] == 'z' && buffer[3] == 'X' &&
                                buffer[4] == 'Z') {
#if HAVE_LIBLZMA
                        DEBUG_PIPELINE("lzma");
                        io = lzma_open(io);
#else
                        fprintf(stderr, "File %s is lzma compressed but libtrace has not been built with lzma support!\n", filename);
                        return NULL;
#endif
                }
	}	
	/* Now open a threaded, peekable reader using the appropriate module
	 * to read the data */

	if (use_threads) {
		DEBUG_PIPELINE("thread");
		io = thread_open(io);
	}
	
	DEBUG_PIPELINE("peek");
	return peek_open(io);
}

DLLEXPORT struct wandio_compression_type *wandio_lookup_compression_type(
        const char *name) {

        struct wandio_compression_type *wct = compression_type;

        while (strcmp(wct->name, "NONE") != 0) {
                if (strcmp(wct->name, name) == 0)
                        return wct;
                wct++;
        }

        return NULL;
}

DLLEXPORT io_t *wandio_create(const char *filename) {
	parse_env();
	return create_io_reader(filename, use_autodetect);
}

DLLEXPORT io_t *wandio_create_uncompressed(const char *filename) {
	parse_env();
	return create_io_reader(filename, 0);
}


DLLEXPORT off_t wandio_tell(io_t *io)
{
	if (!io->source->tell) {
		errno = -ENOSYS;
		return -1;
	}
	return io->source->tell(io);
}

DLLEXPORT off_t wandio_seek(io_t *io, off_t offset, int whence)
{
	if (!io->source->seek) {
		errno = -ENOSYS;
		return -1;
	}
	return io->source->seek(io,offset,whence);
}

DLLEXPORT off_t wandio_read(io_t *io, void *buffer, off_t len)
{ 
	off_t ret;
	ret=io->source->read(io,buffer,len); 
#if READ_TRACE
	fprintf(stderr,"%p: read(%s): %d bytes = %d\n",io,io->source->name, (int)len,(int)ret);
#endif
	return ret;
}

DLLEXPORT off_t wandio_peek(io_t *io, void *buffer, off_t len)
{
	off_t ret;
	assert(io->source->peek); /* If this fails, it means you're calling
				   * peek on something that doesn't support
				   * peeking.   Push a peek_open() on the io
				   * first.
				   */
	ret=io->source->peek(io, buffer, len);
#if READ_TRACE
	fprintf(stderr,"%p: peek(%s): %d bytes = %d\n",io,io->source->name, (int)len, (int)ret);
#endif
	return ret;
}

DLLEXPORT void wandio_destroy(io_t *io)
{ 
	if (!io)
		return;
	
	if (keep_stats) 
		fprintf(stderr,"LIBTRACEIO STATS: %"PRIu64" blocks on read\n", read_waits);
	io->source->close(io); 
}

DLLEXPORT iow_t *wandio_wcreate(const char *filename, int compress_type, int compression_level, int flags)
{
	iow_t *iow;
	parse_env();

	assert ( compression_level >= 0 && compression_level <= 9 );
	assert (compress_type != WANDIO_COMPRESS_MASK);

	iow=stdio_wopen(filename, flags);
	if (!iow)
		return NULL;

	/* We prefer zlib if available, otherwise we'll use bzip. If neither
	 * are present, guess we'll just have to write uncompressed */
#if HAVE_LIBZ
	if (compression_level != 0 && 
	    compress_type == WANDIO_COMPRESS_ZLIB) {
		iow = zlib_wopen(iow,compression_level);
	}
#endif
#if HAVE_LIBLZO2
	else if (compression_level != 0 && 
	    compress_type == WANDIO_COMPRESS_LZO) {
		iow = lzo_wopen(iow,compression_level);
	}
#endif
#if HAVE_LIBBZ2
	else if (compression_level != 0 && 
	    compress_type == WANDIO_COMPRESS_BZ2) {
		iow = bz_wopen(iow,compression_level);
	}
#endif
#if HAVE_LIBLZMA
        else if (compression_level != 0 && 
            compress_type == WANDIO_COMPRESS_LZMA) {
                iow = lzma_wopen(iow,compression_level);
        }
#endif
	/* Open a threaded writer */
	if (use_threads)
		return thread_wopen(iow);
	else
		return iow;
}

DLLEXPORT off_t wandio_wwrite(iow_t *iow, const void *buffer, off_t len)
{
#if WRITE_TRACE
	fprintf(stderr,"wwrite(%s): %d bytes\n",iow->source->name, (int)len);
#endif
	return iow->source->write(iow,buffer,len);	
}

DLLEXPORT void wandio_wdestroy(iow_t *iow)
{
	iow->source->close(iow);
	if (keep_stats) 
		fprintf(stderr,"LIBTRACEIO STATS: %"PRIu64" blocks on write\n", write_waits);
}

