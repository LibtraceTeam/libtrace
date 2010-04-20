/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Daniel Lawson 
 *          Perry Lorier
 *          Shane Alcock 
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

/** @file
 *
 * @brief Header that provides local definitions of the various format
 * identifiers used for printing various numeric types
 */

#ifndef LT_INTTYPES_H
#define LT_INTTYPES_H 1 /**< Include Guard */

#ifndef PRIu64
/* We need PRIu64 and others, but inttypes.h either doesn't exist, or it
 * doesn't have these identifiers. We define them ourselves...
 */

/* The ISO C99 standard specifies that these macros must only be
   defined if explicitly requested.  */
# if !defined __cplusplus || defined __STDC_FORMAT_MACROS

#  if __WORDSIZE == 64
#   define __PRI64_PREFIX        "l"
#   define __PRIPTR_PREFIX       "l"
#  else
#   define __PRI64_PREFIX        "ll"
#   define __PRIPTR_PREFIX
#  endif

#  define PRId8			"d"			/**< Print format for an 8 bit integer */
#  define PRId16		"d"			/**< Print format for a 16 bit integer */
#  define PRId32		"d"			/**< Print format for a 32 bit integer */
#  define PRId64		__PRI64_PREFIX "d"	/**< Print format for a 64 bit integer */

#  define PRIi8			"i"			/**< Print format for an 8 bit integer */
#  define PRIi16		"i"			/**< Print format for a 16 bit integer */
#  define PRIi32		"i"			/**< Print format for a 32 bit integer */
#  define PRIi64		__PRI64_PREFIX "i"	/**< Print format for a 64 bit integer */

#  define PRIo8			"o"			/**< Print format for an 8 bit octal */
#  define PRIo16		"o"			/**< Print format for a 16 bit octal */
#  define PRIo32		"o"			/**< Print format for a 32 bit octal */
#  define PRIo64		__PRI64_PREFIX "o"	/**< Print format for a 64 bit octal */

#  define PRIu8			"u"
#  define PRIu16		"u"
#  define PRIu32		"u"
#  define PRIu64		__PRI64_PREFIX "u"

#  define PRIx8			"x"
#  define PRIx16		"x"
#  define PRIx32		"x"
#  define PRIx64		__PRI64_PREFIX "x"

#  define PRIX8			"X"
#  define PRIX16		"X"
#  define PRIX32		"X"
#  define PRIX64		__PRI64_PREFIX "X"

# endif

# ifndef UINT64_MAX
#  if __WORDSIZE == 64
#   define UINT64_MAX    18446744073709551615UL		/**< Maximum value of a uint64_t */
#  else
#   define UINT64_MAX    18446744073709551615ULL	/**< Maximum value of a uint64_t */
#  endif
# endif

#endif

#endif
