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
#include <sys/uio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

/* Libtrace IO module implementing a standard IO writer, i.e. no decompression
 */

enum { MIN_WRITE_SIZE = 4096 };

struct stdiow_t {
	char buffer[MIN_WRITE_SIZE];
	int offset;
	int fd;
};

extern iow_source_t stdio_wsource;

#define DATA(iow) ((struct stdiow_t *)((iow)->data))

static int safe_open(const char *filename, int flags)
{
	int fd = -1;
	uid_t userid = 0;
	gid_t groupid = 0;
	char *sudoenv = NULL;

/* Try opening with O_DIRECT */
#ifdef O_DIRECT
	fd = open(filename,
		flags
		|O_WRONLY
		|O_CREAT
		|O_TRUNC
		|(force_directio_write?O_DIRECT:0),
		0666);
#endif
/* If that failed (or we don't support O_DIRECT) try opening without */
	if (fd == -1) {
		fd = open(filename,
			flags
			|O_WRONLY
			|O_CREAT
			|O_TRUNC,
			0666);
	}

	if (fd == -1)
		return fd;

	/* If we're running via sudo, we want to write files owned by the
	 * original user rather than root.
	 *
	 * TODO: make this some sort of config option */

	sudoenv = getenv("SUDO_UID");
	if (sudoenv != NULL) {
		userid = strtol(sudoenv, NULL, 10);
	}
	sudoenv = getenv("SUDO_GID");
	if (sudoenv != NULL) {
		groupid = strtol(sudoenv, NULL, 10);
	}
	
	if (userid != 0 && fchown(fd, userid, groupid) == -1) {
		perror("fchown");
		return -1;
	}

	return fd;
}

iow_t *stdio_wopen(const char *filename,int flags)
{
	iow_t *iow = malloc(sizeof(iow_t));
	iow->source = &stdio_wsource;
	iow->data = malloc(sizeof(struct stdiow_t));

	if (strcmp(filename,"-") == 0) 
		DATA(iow)->fd = 1; /* STDOUT */
	else {
		DATA(iow)->fd = safe_open(filename, flags);
	}

	if (DATA(iow)->fd == -1) {
		free(iow);
		return NULL;
	}

	DATA(iow)->offset = 0;

	return iow;
}

#define min(a,b) ((a)<(b) ? (a) : (b))
#define max(a,b) ((a)>(b) ? (a) : (b))
/* Round A Down to the nearest multiple of B */
#define rounddown(a,b) ((a)-((a)%b)

/* When doing directio (O_DIRECT) we need to make sure that we write multiples of MIN_WRITE_SIZE.
 * So we accumulate data into DATA(iow)->buffer, and write it out when we get at least MIN_WRITE_SIZE.
 *
 * Since most writes are likely to be larger than MIN_WRITE_SIZE optimise for that case.
 */
static off_t stdio_wwrite(iow_t *iow, const char *buffer, off_t len)
{
	int towrite = len;
	/* Round down size to the nearest multiple of MIN_WRITE_SIZE */

	assert(towrite >= 0);

	while (DATA(iow)->offset + towrite >= MIN_WRITE_SIZE) {
		int err;
		struct iovec iov[2];
		int total = (DATA(iow)->offset+towrite);
		int amount;
		int count=0;
		/* Round down to the nearest multiple */
		total = total - (total % MIN_WRITE_SIZE);
		amount = total;
		if (DATA(iow)->offset) {
			iov[count].iov_base = DATA(iow)->buffer;
			iov[count].iov_len = min(DATA(iow)->offset,amount);
			amount -= iov[count].iov_len;
			++count;
		}
		/* How much to write from this buffer? */
		if (towrite) {
			iov[count].iov_base = (void*)buffer; 	/* cast away constness, which is safe 
								 * here 
								 */
			iov[count].iov_len = amount;
			amount -= iov[count].iov_len;
			++count;
		}
		assert(amount == 0);
		err=writev(DATA(iow)->fd, iov, count);
		if (err==-1)
			return -1;

		/* Drop off "err" bytes from the beginning of the buffers */
		amount = min(DATA(iow)->offset, err); /* How much we took out of the buffer */
		memmove(DATA(iow)->buffer, 
			DATA(iow)->buffer+amount,
			DATA(iow)->offset-amount);
		DATA(iow)->offset -= amount;

		err -= amount; /* How much was written */

		assert(err <= towrite);

		buffer += err;
		towrite -= err;

		assert(DATA(iow)->offset == 0);
	}

	/* Make sure we're not going to overflow the buffer.  The above writev should assure
 	 * that this is true
 	 */
	assert(DATA(iow)->offset + towrite <= MIN_WRITE_SIZE);
	assert(towrite >= 0);

	if (towrite > 0) {
		/* Copy the remainder into the buffer to write next time. */
		memcpy(DATA(iow)->buffer + DATA(iow)->offset, buffer, towrite);
		DATA(iow)->offset += towrite;
	}

	return len;
}

static void stdio_wclose(iow_t *iow)
{
	long err;
	/* Now, there might be some non multiple of the direct filesize left over, if so turn off
 	 * O_DIRECT and write the final chunk.
 	 */
#ifdef O_DIRECT
	err=fcntl(DATA(iow)->fd, F_GETFL);
	if (err != -1 && (err & O_DIRECT) != 0) {
		fcntl(DATA(iow)->fd,F_SETFL, err & ~O_DIRECT);
	}
#endif
	err=write(DATA(iow)->fd, DATA(iow)->buffer, DATA(iow)->offset);
	DATA(iow)->offset = 0;
	close(DATA(iow)->fd);
	free(iow->data);
	free(iow);
}

iow_source_t stdio_wsource = {
	"stdiow",
	stdio_wwrite,
	stdio_wclose
};
