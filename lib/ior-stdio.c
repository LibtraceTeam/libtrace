#include "wandio.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct stdio_t {
	int fd;
};

extern io_source_t stdio_source;

#define DATA(io) ((struct stdio_t *)((io)->data))

io_t *stdio_open(const char *filename)
{
	io_t *io = malloc(sizeof(io_t));
	io->data = malloc(sizeof(struct stdio_t));

	if (strcmp(filename,"-") == 0)
		DATA(io)->fd = 0; /* STDIN */
	else
		DATA(io)->fd = open(filename,O_RDONLY);
	io->source = &stdio_source;

	if (DATA(io)->fd == -1) {
		free(io);
		return NULL;
	}

	return io;
}

static off_t stdio_read(io_t *io, void *buffer, off_t len)
{
	return read(DATA(io)->fd,buffer,len);
}

static off_t stdio_tell(io_t *io)
{
	return lseek(DATA(io)->fd, 0, SEEK_CUR);
}

static off_t stdio_seek(io_t *io, off_t offset, int whence)
{
	return lseek(DATA(io)->fd, offset, whence);
}

static void stdio_close(io_t *io)
{
	close(DATA(io)->fd);
	free(io->data);
	free(io);
}

io_source_t stdio_source = {
	"stdio",
	stdio_read,
	NULL,
	stdio_tell,
	stdio_seek,
	stdio_close
};

