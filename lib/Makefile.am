lib_LTLIBRARIES = libtrace.la
include_HEADERS = libtrace.h dagformat.h wag.h
#if HAVE_DAG
#libtrace_la_SOURCES = trace.c fifo.c fifo.h common.h dagapi.c dagopts.c
#else
libtrace_la_SOURCES = trace.c fifo.c fifo.h common.h
#endif
libtrace_la_CFLAGS = @ADD_INCLS@
libtrace_la_LIBADD = @ADD_LIBS@ $(top_builddir)/replace/libreplace.a
libtrace_la_LDFLAGS=-version-info 2:14:0 @ADD_LDFLAGS@

dagapi.c:
	cp @DAG_TOOLS_DIR@/dagapi.c .

dagopts.c:
	cp @DAG_TOOLS_DIR@/dagopts.c .
