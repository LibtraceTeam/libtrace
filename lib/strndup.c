/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Matthew Luckie 
 *          
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libtrace; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 *
 */

#include "config.h"

#ifndef HAVE_STRNDUP

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <libtrace_int.h>

/* Some systems don't include strndup as part of their standard C library, so
 * we need to provide our own version.
 *
 * Full credit to Matthew Luckie, who wrote this particular version and allowed
 * us to borrow it.
 */

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
