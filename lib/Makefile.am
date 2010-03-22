lib_LTLIBRARIES = libtrace.la
include_HEADERS = libtrace.h dagformat.h lt_inttypes.h daglegacy.h rt_protocol.h erftypes.h wandio.h

AM_CFLAGS=@LIBCFLAGS@

extra_DIST = format_template.c
if HAVE_NETPACKET_PACKET_H
NATIVEFORMATS=format_linux.c
else
NATIVEFORMATS=
endif

if HAVE_BPF_CAPTURE
BPFFORMATS=format_bpf.c
else
BPFFORMATS=
endif

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

if HAVE_DAG
if DAG2_4
DAGSOURCE=format_dag24.c
else
DAGSOURCE=format_dag25.c
endif
else
DAGSOURCE=
endif
EXTRA_DIST=format_dag24.c format_dag25.c

libtrace_la_SOURCES = trace.c common.h \
		format_erf.c format_pcap.c format_legacy.c \
		format_rt.c format_helper.c format_helper.h format_pcapfile.c \
		format_duck.c format_tsh.c $(NATIVEFORMATS) $(BPFFORMATS) \
		format_atmhdr.c \
		libtrace_int.h lt_inttypes.h \
		linktypes.c link_wireless.c \
		protocols_pktmeta.c protocols_l2.c protocols_l3.c \
		protocols_transport.c protocols.h \
		$(DAGSOURCE) format_erf.h \
		$(LIBTRACEIO_ZLIB) $(LIBTRACEIO_BZLIB) $(LIBTRACEIO_LZO) \
		ior-peek.c ior-stdio.c ior-thread.c \
		iow-stdio.c iow-thread.c wandio.c \
		wandio.h

if DAG2_4
nodist_libtrace_la_SOURCES = dagopts.c dagapi.c
endif

INCLUDES = @ADD_INCLS@
libtrace_la_LIBADD = @ADD_LIBS@ @LTLIBOBJS@
libtrace_la_LDFLAGS=-version-info @LIBTRACE_MAJOR@:@LIBTRACE_MINOR@:@LIBTRACE_MID@ @ADD_LDFLAGS@

dagapi.c:
	cp @DAG_TOOLS_DIR@/dagapi.c .

dagopts.c:
	cp @DAG_TOOLS_DIR@/dagopts.c .
