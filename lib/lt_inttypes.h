#ifndef LT_INTTYPES_H
#define LT_INTTYPES_H 1

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

#  define PRId8			"d"
#  define PRId16		"d"
#  define PRId32		"d"
#  define PRId64		__PRI64_PREFIX "d"

#  define PRIi8			"i"
#  define PRIi16		"i"
#  define PRIi32		"i"
#  define PRIi64		__PRI64_PREFIX "i"

#  define PRIo8			"o"
#  define PRIo16		"o"
#  define PRIo32		"o"
#  define PRIo64		__PRI64_PREFIX "o"

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
#   define UINT64_MAX    18446744073709551615UL
#  else
#   define UINT64_MAX    18446744073709551615ULL
#  endif
# endif

#endif

#endif
