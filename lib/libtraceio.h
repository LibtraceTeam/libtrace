#ifndef LIBTRACEIO_H
#define LIBTRACEIO_H 1
#include "config.h"
#ifdef HAVE_ZLIB
#include <zlib.h>
#else
#include <stdio.h>
#endif

typedef struct libtrace_io_t libtrace_io_t;

/** read a block from a file
 * @param io 	the io file object
 * @param buf 	the buffer to read into
 * @param len	the number of bytes to read
 *
 * @returns -1 on error (with errno set), 0 on eof, otherwise the number of bytes
 * 	read.
 */
ssize_t libtrace_io_read(libtrace_io_t *io, void *buf, size_t len);
/** open a file from a file descriptor (like fdopen(3))
 * @param fd 	file descriptor to read
 * @param mode	text string to represent what mode to read the file in.
 *
 * @returns io object, or NULL on error.
 */
libtrace_io_t *libtrace_io_fdopen(int fd, const char *mode);
/** open a file from a path name
 * @param path	pathname to read
 * @param mode	text string to represent what mode to read the file in.
 *
 * @returns io object, or NULL on error.
 */
libtrace_io_t *libtrace_io_open(const char *path, const char *mode);
/** close a file and free all of it's resources.
 * @param io	io object
 * 
 * This function doesn't return anything.  In theory it could return an error
 * but seriously, if it did return an error, what would you do about it?
 */
void libtrace_io_close(libtrace_io_t *io);

/** write a block of data to a file
 * @param io	libtrace io object to write to
 * @param buf	buffer to write to
 * @param len	number of bytes to write
 *
 * @returns the number of bytes successfully written, or -1 on error with
 * errno set 
 */
ssize_t libtrace_io_write(libtrace_io_t *io, const void *buf, size_t len);
off_t libtrace_io_seek(libtrace_io_t *io, off_t offset, int whence);
ssize_t libtrace_io_tell(libtrace_io_t *io);

#endif
