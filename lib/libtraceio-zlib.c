#include "libtraceio.h"
#include <zlib.h>
#include <stdlib.h>
#include <errno.h>

struct libtrace_io_t {
	gzFile *file;
};

ssize_t libtrace_io_read(libtrace_io_t *io, void *buf, size_t len)
{
	int err=gzread(io->file,buf,len);
	int err2=errno;
	if (err>=0) {
		/* successfully read <x> bytes */
		return err;
	}
	switch(err) {
		case Z_STREAM_END:
			return 0;
		case Z_ERRNO: 
			if (err2==0)
				return 0; /* EOF */
			return -1;
		case Z_MEM_ERROR:
			errno=ENOMEM;
			return -1;
		default:
		      /* Some decompression error or something */
		      errno=EINVAL;
		      return -1;
	}
}

libtrace_io_t *libtrace_io_fdopen(int fd, const char *mode)
{
	libtrace_io_t *io = malloc(sizeof(libtrace_io_t));
	io->file = gzdopen(fd,mode);
	return io;
}

libtrace_io_t *libtrace_io_open(const char *path, const char *mode)
{
	libtrace_io_t *io = malloc(sizeof(libtrace_io_t));
	io->file = gzopen(path,mode);
	return io;
}

/* Technically close returns -1 on failure, but if the close fails, really
 * what are you going to do about it?
 */
void libtrace_io_close(libtrace_io_t *io)
{
	gzclose(io->file);
	io->file=NULL;
	free(io);
}

ssize_t libtrace_io_write(libtrace_io_t *io, const void *buf, size_t len)
{
	return gzwrite(io->file,buf,len);
}

off_t libtrace_io_seek(libtrace_io_t *io, off_t offset, int whence)
{
	return gzseek(io->file,offset,whence);
}

ssize_t libtrace_io_tell(libtrace_io_t *io)
{
	return gztell(io->file);
}
