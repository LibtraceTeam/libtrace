#ifndef IO_H
#define IO_H 1
#include <sys/types.h>
#include <stdio.h>

typedef struct io_t io_t;
typedef struct iow_t iow_t;

struct compression_type {
	const char *name;
	int compress_flag;
	const char *ext;
};
extern struct compression_type compression_type[];

typedef struct {
	const char *name;
	off_t (*read)(io_t *io, void *buffer, off_t len);
	off_t (*peek)(io_t *io, void *buffer, off_t len);
	off_t (*tell)(io_t *io);
	off_t (*seek)(io_t *io, off_t offset, int whence);
	void (*close)(io_t *io);
} io_source_t;

typedef struct {
	const char *name;
	off_t (*write)(iow_t *iow, const char *buffer, off_t len);
	void (*close)(iow_t *iow);
} iow_source_t;

struct io_t {
	io_source_t *source;
	void *data;
};

struct iow_t {
	iow_source_t *source;
	void *data;
};

enum {
	WANDIO_COMPRESS_NONE	= 0,
	WANDIO_COMPRESS_ZLIB	= 1,
	WANDIO_COMPRESS_BZ2	= 2,
	WANDIO_COMPRESS_MASK	= 3
};


io_t *bz_open(io_t *parent);
io_t *zlib_open(io_t *parent);
io_t *thread_open(io_t *parent);
io_t *peek_open(io_t *parent);
io_t *stdio_open(const char *filename);

iow_t *zlib_wopen(iow_t *child, int compress_level);
iow_t *bz_wopen(iow_t *child, int compress_level);
iow_t *thread_wopen(iow_t *child);
iow_t *stdio_wopen(const char *filename);

io_t *wandio_create(const char *filename);
off_t wandio_tell(io_t *io);
off_t wandio_seek(io_t *io, off_t offset, int whence);
off_t wandio_read(io_t *io, void *buffer, off_t len);
off_t wandio_peek(io_t *io, void *buffer, off_t len);
void wandio_destroy(io_t *io);

iow_t *wandio_wcreate(const char *filename, int compression_level, int flags);
off_t wandio_wwrite(iow_t *iow, const void *buffer, off_t len);
void wandio_wdestroy(iow_t *iow);

#endif
