lib_LTLIBRARIES=libwandio.la

include_HEADERS=wandio.h

AM_CFLAGS=@LIBCFLAGS@
AM_CXXFLAGS=@LIBCXXFLAGS@

if HAVE_ZLIB
LIBTRACEIO_ZLIB=ior-zlib.c iow-zlib.c
else
LIBTRACEIO_ZLIB=
endif

if HAVE_BZLIB
LIBTRACEIO_BZLIB=ior-bzip.c iow-bzip.c
else
LIBTRACEIO_BZLIB=
endif

if HAVE_LZO
LIBTRACEIO_LZO=iow-lzo.c
else
LIBTRACEIO_LZO=
endif

libwandio_la_SOURCES=wandio.c ior-peek.c ior-stdio.c ior-thread.c \
		iow-stdio.c iow-thread.c wandio.h \
		$(LIBTRACEIO_ZLIB) $(LIBTRACEIO_BZLIB) $(LIBTRACEIO_LZO)

INCLUDES = @ADD_INCLS@
libwandio_la_LIBADD = @LIBWANDIO_LIBS@
libwandio_la_LDFLAGS=-version-info 1:0:0 @ADD_LDFLAGS@

