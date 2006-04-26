lib_LTLIBRARIES = libtrace.la
include_HEADERS = libtrace.h dagformat.h wag.h lt_inttypes.h daglegacy.h rt_protocol.h libtraceio.h

extra_DIST = format_template.c
libtrace_la_SOURCES = trace.c fifo.c fifo.h common.h \
		format_erf.c format_pcap.c format_wag.c format_legacy.c \
		format_rt.c format_helper.c format_helper.h format_pcapfile.c \
		parse_cmd.c parse_cmd.h libtrace_int.h lt_inttypes.h \
		linktypes.c protocols.c libtraceio.h 
if HAVE_NETPACKET_PACKET_H
libtrace_la_SOURCES+=format_linux.c
endif

if HAVE_ZLIB
libtrace_la_SOURCES+=libtraceio-zlib.c
else
libtrace_la_SOURCES+=libtraceio-stdio.c
endif

if DAG2_4
nodist_libtrace_la_SOURCES = dagopts.c dagapi.c
endif

INCLUDES = @ADD_INCLS@
libtrace_la_LIBADD = @ADD_LIBS@ @LTLIBOBJS@
libtrace_la_LDFLAGS=-version-info 3:0:0 @ADD_LDFLAGS@

dagapi.c:
	cp @DAG_TOOLS_DIR@/dagapi.c .

dagopts.c:
	cp @DAG_TOOLS_DIR@/dagopts.c .
