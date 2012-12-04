lib_LTLIBRARIES = libtrace.la
include_HEADERS = libtrace.h dagformat.h lt_inttypes.h daglegacy.h rt_protocol.h erftypes.h  

AM_CFLAGS=@LIBCFLAGS@
AM_CXXFLAGS=@LIBCXXFLAGS@

extra_DIST = format_template.c
NATIVEFORMATS=format_linux.c
BPFFORMATS=format_bpf.c

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

if HAVE_LLVM
BPFJITSOURCE=bpf-jit/bpf-jit.cc 
else
BPFJITSOURCE=
endif


libtrace_la_SOURCES = trace.c common.h \
		format_erf.c format_pcap.c format_legacy.c \
		format_rt.c format_helper.c format_helper.h format_pcapfile.c \
		format_duck.c format_tsh.c $(NATIVEFORMATS) $(BPFFORMATS) \
		format_atmhdr.c \
		libtrace_int.h lt_inttypes.h \
		linktypes.c link_wireless.c \
		protocols_pktmeta.c protocols_l2.c protocols_l3.c \
		protocols_transport.c protocols.h protocols_ospf.c \
		$(DAGSOURCE) format_erf.h \
		$(BPFJITSOURCE) \
		libtrace_arphrd.h

if DAG2_4
nodist_libtrace_la_SOURCES = dagopts.c dagapi.c
endif

INCLUDES= @ADD_INCLS@ -I../libwandio
libtrace_la_LIBADD = @LIBTRACE_LIBS@ @LTLIBOBJS@
libtrace_la_LDFLAGS=-version-info @LIBTRACE_MAJOR@:@LIBTRACE_MINOR@:@LIBTRACE_MID@ @ADD_LDFLAGS@

dagapi.c:
	cp @DAG_TOOLS_DIR@/dagapi.c .

dagopts.c:
	cp @DAG_TOOLS_DIR@/dagopts.c .

if HAVE_LLVM
# Rules to build the llvm .cc file from a C description of each opcode.
bpf-jit/bpf-opcodes.llvm.bc: bpf-jit/bpf-opcodes.c
	$(LLVM_GCC) -std=c99 -c -O0 -emit-llvm $< -o $@

bpf-jit/bpf-opcodes.llvm.cc: bpf-jit/bpf-opcodes.llvm.bc
	`$(LLVM_CONFIG) --bindir`/llc -march=cpp -cppgen=module $< -o $@

bpf-jit/bpf-jit.cc: bpf-jit/bpf-opcodes.llvm.cc

EXTRA_DIST+=bpf-jit/bpf-opcodes.c
BUILT_SOURCES=bpf-jit/bpf-opcodes.llvm.cc
endif
CLEANFILES=bpf-jit/bpf-opcodes.llvm.cc bpf-jit/bpf-opcodes.llvm.bc
