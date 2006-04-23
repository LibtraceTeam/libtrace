#include "libtrace.h"
#include "libtrace_int.h"
#include "libtraceio.h"
#include <sys/types.h> /* for ssize_t/off_t */
#include <stdio.h>
#include <stdlib.h>

struct libtrace_io_t {
	FILE *file;
};

ssize_t libtrace_io_read(libtrace_io_t *io, void *buf, size_t len)
{
	int ret=fread(buf,1,len,io->file);

	if (ret==(int)len) {
		return len;
	}

	/* EOF or an Error occurred */
	if (ferror(io->file)) {
		/* errno will be set */
		return -1;
	}

	return 0; /* EOF */
}

libtrace_io_t *libtrace_io_fdopen(int fd, const char *mode)
{
	libtrace_io_t *io = malloc(sizeof(libtrace_io_t));
	io->file = fdopen(fd,mode);
	return io;
}

libtrace_io_t *libtrace_io_open(const char *path, const char *mode)
{
	libtrace_io_t *io = malloc(sizeof(libtrace_io_t));
	io->file = fopen(path,mode);
	return io;
}

/* Technically close returns -1 on failure, but if the close fails, really
 * what are you going to do about it?
 */
void libtrace_io_close(libtrace_io_t *io)
{
	fclose(io->file);
	io->file=NULL;
	free(io);
}

ssize_t libtrace_io_write(libtrace_io_t *io, const void *buf, size_t len)
{
	int ret=fwrite(buf,1,len,io->file);
	if (ret==len) {
		return ret;
	}
	
	/* Error occurred? */
	if (ferror(io->file))
		return -1; /* errno will already be set */

	return 0; /* eof */
}

off_t libtrace_io_seek(libtrace_io_t *io, off_t offset, int whence)
{
	return fseek(io->file,offset,whence);
}

ssize_t libtrace_io_tell(libtrace_io_t *io)
{
	return ftell(io->file);
}
