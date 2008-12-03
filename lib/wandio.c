#include "wandio.h"
#include "config.h"
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

struct compression_type compression_type[]  = {
	{ "GZ",		WANDIO_COMPRESS_ZLIB, 	"gz" },
	{ "BZ2",	WANDIO_COMPRESS_BZ2, 	"bz2" },
	{ "NONE",	WANDIO_COMPRESS_NONE,	""}
};

#define READ_TRACE 0
#define WRITE_TRACE 0

io_t *wandio_create(const char *filename)
{
	io_t *io = peek_open(stdio_open(filename));
	char buffer[1024];
	if (!io)
		return NULL;
	wandio_peek(io, buffer, sizeof(buffer));
#if HAVE_LIBZ
	/* auto detect gzip compressed data */
	if (buffer[0] == '\037' && buffer[1] == '\213') { 
		io = zlib_open(io);
	}
	/* auto detect compress(1) compressed data (gzip can read this) */
	if (buffer[0] == '\037' && buffer[1] == '\235') {
		io = zlib_open(io);
	}
#endif
#if HAVE_LIBBZ2
	/* auto detect bzip compressed data */
	else if (buffer[0] == 'B' && buffer[1] == 'Z' && buffer[2] == 'h') { 
		io = bz_open(io);
	}
#endif
	return thread_open(io);
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
{ io->source->close(io); }

iow_t *wandio_wcreate(const char *filename, int compression_level, int flags)
{
	iow_t *iow;

	assert ( compression_level >= 0 && compression_level <= 9 );

	iow=stdio_wopen(filename);
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
	return thread_wopen(iow);
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
}

