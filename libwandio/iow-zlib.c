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


#include <zlib.h>
#include "wandio.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Libtrace IO module implementing a zlib writer */

enum err_t {
	ERR_OK	= 1,
	ERR_EOF = 0,
	ERR_ERROR = -1
};

struct zlibw_t {
	z_stream strm;
	Bytef outbuff[1024*1024];
	iow_t *child;
	enum err_t err;
	int inoffset;
};


extern iow_source_t zlib_wsource; 

#define DATA(iow) ((struct zlibw_t *)((iow)->data))
#define min(a,b) ((a)<(b) ? (a) : (b))

iow_t *zlib_wopen(iow_t *child, int compress_level)
{
	iow_t *iow;
	if (!child)
		return NULL;
	iow = malloc(sizeof(iow_t));
	iow->source = &zlib_wsource;
	iow->data = malloc(sizeof(struct zlibw_t));

	DATA(iow)->child = child;

	DATA(iow)->strm.next_in = NULL;
	DATA(iow)->strm.avail_in = 0;
	DATA(iow)->strm.next_out = DATA(iow)->outbuff;
	DATA(iow)->strm.avail_out = sizeof(DATA(iow)->outbuff);
	DATA(iow)->strm.zalloc = Z_NULL;
	DATA(iow)->strm.zfree = Z_NULL;
	DATA(iow)->strm.opaque = NULL;
	DATA(iow)->err = ERR_OK;

	deflateInit2(&DATA(iow)->strm, 
			compress_level,	/* Level */
			Z_DEFLATED, 	/* Method */
			15 | 16, 	/* 15 bits of windowsize, 16 == use gzip header */
			9,		/* Use maximum (fastest) amount of memory usage */
			Z_DEFAULT_STRATEGY
		);

	return iow;
}


static off_t zlib_wwrite(iow_t *iow, const char *buffer, off_t len)
{
	if (DATA(iow)->err == ERR_EOF) {
		return 0; /* EOF */
	}
	if (DATA(iow)->err == ERR_ERROR) {
		return -1; /* ERROR! */
	}

	DATA(iow)->strm.next_in = (Bytef*)buffer; /* This casts away const, but it's really const 
						   * anyway 
						   */
	DATA(iow)->strm.avail_in = len;

	while (DATA(iow)->err == ERR_OK && DATA(iow)->strm.avail_in > 0) {
		while (DATA(iow)->strm.avail_out <= 0) {
			int bytes_written = wandio_wwrite(DATA(iow)->child, 
				(char *)DATA(iow)->outbuff,
				sizeof(DATA(iow)->outbuff));
			if (bytes_written <= 0) { /* Error */
				DATA(iow)->err = ERR_ERROR;
				/* Return how much data we managed to write ok */
				if (DATA(iow)->strm.avail_in != (uint32_t)len) {
					return len-DATA(iow)->strm.avail_in;
				}
				/* Now return error */
				return -1;
			}
			DATA(iow)->strm.next_out = DATA(iow)->outbuff;
			DATA(iow)->strm.avail_out = sizeof(DATA(iow)->outbuff);
		}
		/* Decompress some data into the output buffer */
		int err=deflate(&DATA(iow)->strm, 0);
		switch(err) {
			case Z_OK:
				DATA(iow)->err = ERR_OK;
				break;
			default:
				DATA(iow)->err = ERR_ERROR;
		}
	}
	/* Return the number of bytes decompressed */
	return len-DATA(iow)->strm.avail_in;
}

static void zlib_wclose(iow_t *iow)
{
	int res;
	
	while (1) {
		res = deflate(&DATA(iow)->strm, Z_FINISH);

		if (res == Z_STREAM_END)
			break;
		if (res == Z_STREAM_ERROR) {
			fprintf(stderr, "Z_STREAM_ERROR while closing output\n");
			break;
		}
	
		wandio_wwrite(DATA(iow)->child, 
				(char*)DATA(iow)->outbuff,
				sizeof(DATA(iow)->outbuff)-DATA(iow)->strm.avail_out);
		DATA(iow)->strm.next_out = DATA(iow)->outbuff;
		DATA(iow)->strm.avail_out = sizeof(DATA(iow)->outbuff);
	}

	deflateEnd(&DATA(iow)->strm);
	wandio_wwrite(DATA(iow)->child, 
			(char *)DATA(iow)->outbuff,
			sizeof(DATA(iow)->outbuff)-DATA(iow)->strm.avail_out);
	wandio_wdestroy(DATA(iow)->child);
	free(iow->data);
	free(iow);
}

iow_source_t zlib_wsource = {
	"zlibw",
	zlib_wwrite,
	zlib_wclose
};

