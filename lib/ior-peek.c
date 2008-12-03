#include "wandio.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct peek_t {
	io_t *child;
	char *buffer;
	int length;
	int offset;
};

extern io_source_t peek_source;

#define DATA(io) ((struct peek_t *)((io)->data))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

io_t *peek_open(io_t *child)
{
	io_t *io;
	if (!child)
		return NULL;
	io =  malloc(sizeof(io_t));
	io->data = malloc(sizeof(struct peek_t));
	io->source = &peek_source;

	DATA(io)->child = child;
	DATA(io)->buffer = NULL;
	DATA(io)->length = 0;

	return io;
}

static off_t peek_read(io_t *io, void *buffer, off_t len)
{
	off_t ret = 0;

	/* Is some of this data in the buffer? */
	if (DATA(io)->buffer) {
		ret = MIN(len,DATA(io)->length - DATA(io)->offset);

		memcpy(buffer, 
			DATA(io)->buffer + DATA(io)->offset,
			ret);
		buffer += ret;
		DATA(io)->offset += ret;
		len -= ret;
	}
	/* Copy the rest of the data from the child */
	if (len>0) {
		off_t bytes_read = 
			DATA(io)->child->source->read(
				DATA(io)->child, buffer, len);
		/* Error? */
		if (bytes_read < 1) {
			/* Return if we have managed to get some data ok */
			if (ret > 0)
				return ret;
			/* Return the error upstream */
			return bytes_read;
		}
		ret += bytes_read;
	}

	/* Have we read past the end of the buffer? */
	if (DATA(io)->buffer && DATA(io)->offset >= DATA(io)->length) {
		/* If so, free the memory it used */
		free(DATA(io)->buffer);
		DATA(io)->buffer = NULL;
		DATA(io)->offset = 0;
		DATA(io)->length = 0;
	}

	return ret;
}

/* Round reads for peeks into the buffer up to this size */
#define PEEK_SIZE (1024*1024)

static off_t peek_peek(io_t *io, void *buffer, off_t len)
{
	off_t ret = 0;

	/* Is there enough data in the buffer to serve this request? */
	if (DATA(io)->length - DATA(io)->offset < len) {
		/* No, we need to extend the buffer. */
		off_t read_amount = len - (DATA(io)->length - DATA(io)->offset);
		/* Round the read_amount up to the nearest MB */
		read_amount += PEEK_SIZE - ((DATA(io)->length + read_amount) % PEEK_SIZE);
		DATA(io)->buffer = realloc(DATA(io)->buffer, DATA(io)->length + read_amount);
		read_amount = wandio_read(DATA(io)->child, 
			DATA(io)->buffer + DATA(io)->length,
			read_amount);

		/* Pass errors up */
		if (read_amount <1) {
			return read_amount;
		}

		DATA(io)->length += read_amount;
	}

	/* Right, now return data from the buffer (that now should be large enough, but might
	 * not be if we hit EOF) */
	ret = MIN(len, DATA(io)->length - DATA(io)->offset);
	memcpy(buffer, DATA(io)->buffer + DATA(io)->offset, ret);
	return ret;
}

static off_t peek_tell(io_t *io)
{
	return wandio_tell(DATA(io)->child);
}

static off_t peek_seek(io_t *io, off_t offset, int whence)
{
	return wandio_seek(DATA(io)->child,offset,whence);
}

static void peek_close(io_t *io)
{
	wandio_destroy(DATA(io)->child);
	if (DATA(io)->buffer)
		free(DATA(io)->buffer);
	free(io->data);
	free(io);
}

io_source_t peek_source = {
	"peek",
	peek_read,
	peek_peek,
	peek_tell,
	peek_seek,
	peek_close
};

