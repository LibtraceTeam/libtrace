lib_LTLIBRARIES = libtrace.la
include_HEADERS = libtrace.h dagformat.h wag.h
if HAVE_DAG
libtrace_la_SOURCES = trace.c fifo.c fifo.h common.h
else
libtrace_la_SOURCES = trace.c fifo.c fifo.h common.h
endif
libtrace_la_CFLAGS = @ADD_INCLS@
libtrace_la_LIBADD = @ADD_LIBS@
libtrace_la_LDFLAGS=-version-info 2:9:0 @ADD_LDFLAGS@
