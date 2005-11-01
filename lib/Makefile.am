lib_LTLIBRARIES = libtrace.la
include_HEADERS = libtrace.h dagformat.h wag.h daglegacy.h

if DAG2_4
libtrace_la_SOURCES = trace.c fifo.c fifo.h common.h format_template.c format_erf.c format_pcap.c format_wag.c format_helper.c format_helper.h parse_cmd.c parse_cmd.h libtrace_int.h daglegacy.h
nodist_libtrace_la_SOURCES = dagopts.c dagapi.c
else
libtrace_la_SOURCES = trace.c fifo.c fifo.h common.h format_template.c format_erf.c format_pcap.c format_wag.c format_helper.c format_helper.h parse_cmd.c parse_cmd.h libtrace_int.h daglegacy.h
endif

INCLUDES = @ADD_INCLS@
libtrace_la_LIBADD = @ADD_LIBS@ @LTLIBOBJS@
libtrace_la_LDFLAGS=-version-info 2:24:0 @ADD_LDFLAGS@

dagapi.c:
	cp @DAG_TOOLS_DIR@/dagapi.c .

dagopts.c:
	cp @DAG_TOOLS_DIR@/dagopts.c .
