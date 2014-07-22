/*
 * This file is part of libtrace
 *
 * Copyright (c) 2014 The University of Waikato, Hamilton,
 * New Zealand.
 *
 * Authors: Perry Lorier
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


#include <lzma.h>
#include "wandio.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Libtrace IO module implementing an lzma writer */

enum err_t {
	ERR_OK	= 1,
	ERR_EOF = 0,
	ERR_ERROR = -1
};

struct lzmaw_t {
	lzma_stream strm;
	uint8_t outbuff[1024*1024];
	iow_t *child;
	enum err_t err;
	int inoffset;
};


extern iow_source_t lzma_wsource;

#define DATA(iow) ((struct lzmaw_t *)((iow)->data))
#define min(a,b) ((a)<(b) ? (a) : (b))

iow_t *lzma_wopen(iow_t *child, int compress_level)
{
	iow_t *iow;
	if (!child)
		return NULL;
	iow = malloc(sizeof(iow_t));
	iow->source = &lzma_wsource;
	iow->data = malloc(sizeof(struct lzmaw_t));

	DATA(iow)->child = child;

        memset(&DATA(iow)->strm, 0, sizeof(DATA(iow)->strm));
	DATA(iow)->strm.next_out = DATA(iow)->outbuff;
	DATA(iow)->strm.avail_out = sizeof(DATA(iow)->outbuff);
	DATA(iow)->err = ERR_OK;

        if (lzma_easy_encoder(&DATA(iow)->strm,
                    compress_level,
                    LZMA_CHECK_CRC64) != LZMA_OK) {
            free(iow->data);
            free(iow);
            return NULL;
        }

	return iow;
}


static off_t lzma_wwrite(iow_t *iow, const char *buffer, off_t len)
{
	if (DATA(iow)->err == ERR_EOF) {
		return 0; /* EOF */
	}
	if (DATA(iow)->err == ERR_ERROR) {
		return -1; /* ERROR! */
	}

        DATA(iow)->strm.next_in = (const uint8_t*)buffer;
	DATA(iow)->strm.avail_in = len;

	while (DATA(iow)->err == ERR_OK && DATA(iow)->strm.avail_in > 0) {
                /* Flush output data. */
		while (DATA(iow)->strm.avail_out <= 0) {
			int bytes_written = wandio_wwrite(DATA(iow)->child,
				DATA(iow)->outbuff,
				sizeof(DATA(iow)->outbuff));
			if (bytes_written <= 0) { /* Error */
				DATA(iow)->err = ERR_ERROR;
				/* Return how much data we managed to write */
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
		lzma_ret err=lzma_code(&DATA(iow)->strm, LZMA_RUN);
		switch(err) {
			case LZMA_OK:
				DATA(iow)->err = ERR_OK;
				break;
			default:
				DATA(iow)->err = ERR_ERROR;
		}
	}
	/* Return the number of bytes decompressed */
	return len-DATA(iow)->strm.avail_in;
}

static void lzma_wclose(iow_t *iow)
{
	lzma_ret res;
	while (1) {
		res = lzma_code(&DATA(iow)->strm, LZMA_FINISH);

		if (res == LZMA_STREAM_END)
			break;
		if (res != LZMA_OK) {
			fprintf(stderr, "Z_STREAM_ERROR while closing output\n");
			break;
		}

		wandio_wwrite(DATA(iow)->child,
				(char*)DATA(iow)->outbuff,
				sizeof(DATA(iow)->outbuff)-DATA(iow)->strm.avail_out);
		DATA(iow)->strm.next_out = DATA(iow)->outbuff;
		DATA(iow)->strm.avail_out = sizeof(DATA(iow)->outbuff);
	}

	wandio_wwrite(DATA(iow)->child,
			(char *)DATA(iow)->outbuff,
			sizeof(DATA(iow)->outbuff)-DATA(iow)->strm.avail_out);
	lzma_end(&DATA(iow)->strm);
	wandio_wdestroy(DATA(iow)->child);
	free(iow->data);
	free(iow);
}

iow_source_t lzma_wsource = {
	"xz",
	lzma_wwrite,
	lzma_wclose
};

