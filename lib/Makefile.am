lib_LTLIBRARIES = libtrace.la
include_HEADERS = libtrace.h dagformat.h wag.h 

if DAG2_4
libtrace_la_SOURCES = trace.c fifo.c fifo.h common.h format_template.c format_erf.c format_pcap.c format_wag.c format_helper.c format_helper.h parse_cmd.c parse_cmd.h libtrace_int.h dagopts.c dagapi.c
else
libtrace_la_SOURCES = trace.c fifo.c fifo.h common.h format_template.c format_erf.c format_pcap.c format_wag.c format_helper.c format_helper.h parse_cmd.c parse_cmd.h libtrace_int.h
endif

libtrace_la_CFLAGS = @ADD_INCLS@
libtrace_la_LIBADD = @ADD_LIBS@ @LTLIBOBJS@
libtrace_la_LDFLAGS=-version-info 2:22:0 @ADD_LDFLAGS@
#libtrace_la_DEPENDENCIES = @DAGSOURCES@

#dagapi.c:
#	cp @DAG_TOOLS_DIR@/dagapi.c .

#dagopts.c:
#	cp @DAG_TOOLS_DIR@/dagopts.c .
