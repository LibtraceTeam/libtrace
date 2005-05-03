lib_LTLIBRARIES = libtrace.la
include_HEADERS = libtrace.h dagformat.h wag.h
libtrace_la_SOURCES = trace.c fifo.c fifo.h common.h 
libtrace_la_CFLAGS = @ADD_INCLS@
libtrace_la_LIBADD = @ADD_LIBS@ @LTLIBOBJS@
libtrace_la_LDFLAGS=-version-info 2:17:0 @ADD_LDFLAGS@

dagapi.c:
	cp @DAG_TOOLS_DIR@/dagapi.c .

dagopts.c:
	cp @DAG_TOOLS_DIR@/dagopts.c .
