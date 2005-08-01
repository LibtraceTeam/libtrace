lib_LTLIBRARIES = libtrace.la
include_HEADERS = libtrace.h dagformat.h wag.h
libtrace_la_SOURCES = trace.c fifo.c fifo.h common.h format_template.c format_erf.c format_pcap.c format_wag.c rtserver.c rtserver.h
libtrace_la_CFLAGS = @ADD_INCLS@
libtrace_la_LIBADD = @ADD_LIBS@ @LTLIBOBJS@
libtrace_la_LDFLAGS=-version-info 2:19:0 @ADD_LDFLAGS@

#dagapi.c:
#	cp @DAG_TOOLS_DIR@/dagapi.c .
#
#dagopts.c:
#	cp @DAG_TOOLS_DIR@/dagopts.c .
