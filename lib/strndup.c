/*
 * Written by mjl. Needs attributation?
 */
#include "../config.h"

#ifndef HAVE_STRNDUP

#include <stdlib.h>
#include <errno.h>
#include <string.h>

char *strndup(const char *s, size_t size)
{
  char   *str;
  size_t  len;

  if(size == 0 || s == NULL)
    {
      errno = EINVAL;
      return NULL;
    }

  if(size > (len = strlen(s)))
    {
      size = len+1;
    }

  if((str = malloc(size)) == NULL)
    {
      errno = ENOMEM;
      return NULL;
    }

  memcpy(str, s, size);
  str[size-1] = '\0';

  return str;
}

#endif
