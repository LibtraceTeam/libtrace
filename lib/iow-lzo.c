/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
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
 * $Id: iow-zlib.c 1521 2010-02-08 22:21:16Z salcock $
 *
 */


#include <lzo/lzo1x.h>
#include "wandio.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> /* for mtime */
#include <errno.h>
#include <assert.h>
#include <inttypes.h>
#include <arpa/inet.h>

enum { 
	M_LZO1X_1     =     1,
	M_LZO1X_1_15  =     2,
	M_LZO1X_999   =     3,
	M_NRV1A       =  0x1a,
	M_NRV1B       =  0x1b,
	M_NRV2A       =  0x2a,
	M_NRV2B       =  0x2b,
	M_NRV2D       =  0x2d,
	M_ZLIB        =   128,
};

const int F_OS_UNIX   = 0x03000000L;
const int F_OS_MASK   = 0xff000000L;

const int F_CS_NATIVE = 0x00000000L;
const int F_CS_MASK   = 0x00f00000L;

const int F_H_CRC32   = 0x00001000L;
const int F_ADLER32_D = 0x00000001L;
const int F_ADLER32_C = 0x00000002L;

static const unsigned char lzop_magic[9] =
    { 0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a };


/* Libtrace IO module implementing a lzo writer */

enum err_t {
	ERR_OK	= 1,
	ERR_EOF = 0,
	ERR_ERROR = -1
};

const int ADLER32_INIT_VALUE = 1;
const int CRC32_INIT_VALUE = 0;

struct lzow_t {
	uint8_t outbuff[1024*1024];
	iow_t *child;
	enum err_t err;
	int inoffset;
	int outoffset;
	void *buffer;
};

extern iow_source_t lzo_wsource; 

#define DATA(iow) ((struct lzow_t *)((iow)->data))
#define min(a,b) ((a)<(b) ? (a) : (b))

static void write_buf(iow_t *iow,const void *data, size_t len)
{
	assert(DATA(iow)->outoffset + len < sizeof(DATA(iow)->outbuff) && "Exceeded output buffer size in lzo compressor");
	memcpy(&DATA(iow)->outbuff[DATA(iow)->outoffset], data, len);
	DATA(iow)->outoffset += len;
}

static void write32(iow_t *iow, uint32_t value)
{
	value = htonl(value);
	write_buf(iow, &value, sizeof(value));
}

static void write16(iow_t *iow, uint16_t value)
{
	value = htons(value);
	write_buf(iow, &value, sizeof(value));
}

static void write8(iow_t *iow, uint8_t value)
{
	write_buf(iow, &value, sizeof(value));
}

iow_t *lzo_wopen(iow_t *child, int compress_level)
{
	const int opt_filter = 0;
	int flags;
	iow_t *iow;

	if (!child)
		return NULL;

	if (lzo_init() != LZO_E_OK) {
		/* Fail */
		return NULL;
	}

	iow = malloc(sizeof(iow_t));
	iow->source = &lzo_wsource;
	iow->data = malloc(sizeof(struct lzow_t));

	DATA(iow)->child = child;
	DATA(iow)->err = ERR_OK;

	DATA(iow)->outoffset = 0;
	DATA(iow)->buffer = malloc(LZO1X_1_MEM_COMPRESS);


	flags = 0;
	flags |= F_OS_UNIX & F_OS_MASK;	/* Operating System */
	flags |= F_CS_NATIVE & F_CS_MASK;	/* Character Set */
	flags |= F_ADLER32_D; /* We adler32 the uncompressed data */
	/* flags |= F_STDIN; */
	/* flags |= F_STDOUT */
	/* flags |= F_MULTIPART; */
	/* flags |= F_H_CRC32; */

	write_buf(iow, lzop_magic, sizeof(lzop_magic));
	write16(iow, 0x1010 &0xFFFF); /* version: pretend to be LZOP version 0x1010 from lzop's version.h */
	write16(iow, lzo_version() & 0xFFFF); /* libversion */
	write16(iow, opt_filter ? 0x0950 : 0x0940); /* version needed to extract */
	write8(iow, M_LZO1X_1);	/* method */
	write8(iow, 5); /* level */
	write32(iow, flags); /* flags */
	/* if (flags & F_H_FILTER) 
		write32(iow, opt_filter); 
	*/ 
	write32(iow, 0x600); /* mode: We assume traces may be sensitive */
	write32(iow, time(NULL)); /* mtime */
	write32(iow, 0); /* GMTdiff */

	/* Length, filename */
	write8(iow, strlen("compresseddata"));
	write_buf(iow, "compresseddata",strlen("compresseddata"));

	if (flags & F_H_CRC32) {
		write32(iow, lzo_crc32(CRC32_INIT_VALUE, DATA(iow)->outbuff, DATA(iow)->outoffset));
	}
	else {
		uint32_t chksum=lzo_adler32(
			ADLER32_INIT_VALUE, 
			DATA(iow)->outbuff+sizeof(lzop_magic), 
			DATA(iow)->outoffset-sizeof(lzop_magic));
		fprintf(stderr,"writing adler32 checksum (%08x)\n",chksum);
		write32(iow, chksum);
	}

	wandio_wwrite(DATA(iow)->child,
		(char *)DATA(iow)->outbuff,
		DATA(iow)->outoffset);
	DATA(iow)->outoffset = 0;

	return iow;
}

static off_t lzo_wwrite_block(iow_t *iow, const char *buffer, off_t len)
{
	char b2[1024*1024];
	int err;
	lzo_uint dst_len;
	
	if (DATA(iow)->err == ERR_EOF) {
		return 0; /* EOF */
	}
	if (DATA(iow)->err == ERR_ERROR) {
		return -1; /* ERROR! */
	}

	err=lzo1x_1_compress((void*)buffer, len, (void*)b2, &dst_len, DATA(iow)->buffer);

	switch(err) {
		case LZO_E_OK:
			break;
		case LZO_E_ERROR:
			DATA(iow)->err = EINVAL; /* "WTF?" */
			break;
		case LZO_E_OUT_OF_MEMORY:
			DATA(iow)->err = ENOMEM; 
			break;
		case LZO_E_NOT_COMPRESSIBLE:
			DATA(iow)->err = EINVAL; /* Claimed not to be used, dunno what we'll do */
			break;
		case LZO_E_INPUT_OVERRUN:
			DATA(iow)->err = EINVAL; 
			break;
		case LZO_E_OUTPUT_OVERRUN:
			DATA(iow)->err = ENOMEM;
			break;
		case LZO_E_LOOKBEHIND_OVERRUN:
			DATA(iow)->err = EINVAL;
			break;
		case LZO_E_EOF_NOT_FOUND:
			DATA(iow)->err = ENOENT;
			break;
		case LZO_E_INPUT_NOT_CONSUMED:
			DATA(iow)->err = EINVAL;
			break;
		case LZO_E_NOT_YET_IMPLEMENTED:
			DATA(iow)->err = ENOSYS;
			break;
		default:
			fprintf(stderr,"Unknown lzo error %d\n",err);
			DATA(iow)->err = EINVAL;
			break;
	}

	write32(iow, len); /* Original length */
	write32(iow, min((uint32_t)len,(uint32_t)dst_len));
	/* CRC32 of the uncompressed buffer */
#if 0
	write32(iow, lzo_crc32(CRC32_INIT_VALUE, (void*)buffer, len));
#endif
	write32(iow, lzo_adler32(ADLER32_INIT_VALUE, (const void*)buffer, len));
	write_buf(iow, b2, dst_len);

	/* Flush the data out */
	wandio_wwrite(DATA(iow)->child,
		(char *)DATA(iow)->outbuff,
		DATA(iow)->outoffset);
	DATA(iow)->outoffset = 0;

	/* Return the number of bytes compressed */
	return len;
}

static off_t lzo_wwrite(iow_t *iow, const char *buffer, off_t len)
{
	/* lzo can only deal with blocks up to 256k */
	off_t ret = 0;
	while (len>0) {
		off_t size = (len >= 256*1024 ? 256*1024 : len);
		off_t err;

		err=lzo_wwrite_block(iow, buffer, size);

		if (err < 0) {/* Error */
			if (ret == 0)
				return err;
			/* If we've written some data, return that fact now, let them call back
			 * and try and write more data, fail again then. 
			 */
			return ret;
		}
		else {
			assert(err == size);
			buffer += size;
			len -= size;
		}
	}
	return ret;
}

static void lzo_wclose(iow_t *iow)
{
	const uint32_t zero = 0;
	/* Write out an end of file marker */
	wandio_wwrite(DATA(iow)->child,
		&zero,
		sizeof(zero));
	wandio_wdestroy(DATA(iow)->child);
	free(DATA(iow)->buffer);
	free(iow->data);
	free(iow);
}

iow_source_t lzo_wsource = {
	"lzo",
	lzo_wwrite,
	lzo_wclose
};

