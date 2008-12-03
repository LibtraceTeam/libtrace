#include "wandio.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct stdiow_t {
	int fd;
};

extern iow_source_t stdio_wsource;

#define DATA(iow) ((struct stdiow_t *)((iow)->data))

iow_t *stdio_wopen(const char *filename)
{
	iow_t *iow = malloc(sizeof(iow_t));
	iow->source = &stdio_wsource;
	iow->data = malloc(sizeof(struct stdiow_t));

	if (strcmp(filename,"-") == 0) 
		DATA(iow)->fd = 1; /* STDOUT */
	else
		DATA(iow)->fd = open(filename,O_WRONLY|O_CREAT|O_TRUNC,0666);

	if (DATA(iow)->fd == -1) {
		free(iow);
		return NULL;
	}

	return iow;
}

static off_t stdio_wwrite(iow_t *iow, const char *buffer, off_t len)
{
	return write(DATA(iow)->fd,buffer,len);
}

static void stdio_wclose(iow_t *iow)
{
	close(DATA(iow)->fd);
	free(iow->data);
	free(iow);
}

iow_source_t stdio_wsource = {
	"stdiow",
	stdio_wwrite,
	stdio_wclose
};
