lib_LTLIBRARIES = libtrace.la
include_HEADERS = libtrace.h dagformat.h wag.h
libtrace_la_SOURCES = trace.c fifo.c fifo.h common.h @DAG_SOURCES@
#dagapi.c dagopts.c
libtrace_la_CFLAGS = @ADD_INCLS@
libtrace_la_LIBADD = @ADD_LIBS@
libtrace_la_LDFLAGS=-version-info 2:8:0 @ADD_LDFLAGS@
