#ifndef LIBTRACEIO_H
#define LIBTRACEIO_H 1
#include "config.h"
#ifdef HAVE_ZLIB
#include <zlib.h>
#else
#include <stdio.h>
#endif

typedef struct libtrace_io_t libtrace_io_t;

ssize_t libtrace_io_read(libtrace_io_t *io, void *buf, size_t len);
libtrace_io_t *libtrace_io_fdopen(int fd, const char *mode);
libtrace_io_t *libtrace_io_open(const char *path, const char *mode);
void libtrace_io_close(libtrace_io_t *io);
ssize_t libtrace_io_write(libtrace_io_t *io, const void *buf, size_t len);
off_t libtrace_io_seek(libtrace_io_t *io, off_t offset, int whence);
ssize_t libtrace_io_tell(libtrace_io_t *io);

#endif
