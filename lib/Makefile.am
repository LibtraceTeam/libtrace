lib_LTLIBRARIES = libtrace.la
libtrace_la_SOURCES = trace.c fifo.c fifo.h common.h
include_HEADERS = libtrace.h dagformat.h wag.h
libtrace_la_LIBADD = @LIBPCAP@ @LIBZ@
libtrace_la_LDFLAGS=-version-info 3:0:1 @LIBPCAP_PATH@ @LIBZ_PATH@
