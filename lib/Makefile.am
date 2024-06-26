lib_LTLIBRARIES = libtrace.la
include_HEADERS = libtrace.h libtrace_parallel.h
pkginclude_HEADERS = dagformat.h lt_inttypes.h daglegacy.h \
        rt_protocol.h erftypes.h pthread_spinlock.h format_ndag.h \
        data-struct/ring_buffer.h data-struct/object_cache.h \
        data-struct/vector.h \
        data-struct/deque.h data-struct/linked_list.h \
        data-struct/buckets.h data-struct/sliding_window.h \
	data-struct/message_queue.h hash_toeplitz.h \
        data-struct/simple_circular_buffer.h \
        libtrace_radius.h

AM_CFLAGS=@LIBCFLAGS@ @CFLAG_VISIBILITY@ -pthread -std=gnu99
AM_CXXFLAGS=@LIBCXXFLAGS@ @CFLAG_VISIBILITY@ -pthread -std=gnu99

extra_DIST = format_template.c
NATIVEFORMATS=format_linux_common.c format_linux_ring.c format_linux_int.c format_linux_common.h
BPFFORMATS=format_bpf.c format_bpf.h
LINUX_SOURCES=

if HAVE_DAG
if DAG2_4
DAGSOURCE=format_dag24.c
else
DAGSOURCE=format_dag25.c
endif
else
DAGSOURCE=
endif
EXTRA_DIST=format_dag24.c format_dag25.c dpdk_libtrace.mk

if HAVE_LLVM
BPFJITSOURCE=bpf-jit/bpf-jit.cc
else
BPFJITSOURCE=
endif

if HAVE_DPDK
NATIVEFORMATS+= format_dpdk.c format_dpdkndag.c format_dpdk.h
# So we also make libtrace.mk in dpdk otherwise automake tries to expand
# it too early which I cannot seem to stop unless we use a path that
# doesn't exist currently
export RTE_SDK=@RTE_SDK@
export RTE_TARGET=@RTE_TARGET@
targs = $(subst -, ,${RTE_TARGET})

export RTE_EXEC_ENV=$(word 3, ${targs})
export RTE_TOOLCHAIN=$(word 4, ${targs})
export RTE_ARCH=$(word 1, ${targs})
export RTE_MACHINE=$(word 2, ${targs})
export RTE_OUTPUT=${RTE_SDK}/${RTE_TARGET}
export RTE_SDK_BIN=${RTE_OUTPUT}

export SAVED_CFLAGS:=$(CFLAGS)
export SAVED_CXXFLAGS:=$(CXXFLAGS)
export SAVED_CPPFLAGS:=$(CPPFLAGS)
export SAVED_LDFLAGS:=$(LDFLAGS)

if HAVE_DPDK_PKGCONFIG
else
include ${RTE_SDK}/mk/target/generic/rte.vars.mk
include ${RTE_SDK}/mk/internal/rte.extvars.mk
endif
# We need to add -Wl before the linker otherwise this breaks our build
# And include any libraries that DPDK might depend upon
export DPDK_LIBTRACE_MK=dpdk_libtrace.mk
include $(DPDK_LIBTRACE_MK)
export CFLAGS += $(SAVED_CFLAGS)
export CXXFLAGS += $(SAVED_CXXFLAGS)
export CPPFLAGS:=$(SAVED_CPPFLAGS)
export LDFLAGS += $(SAVED_LDFLAGS)
endif

if HAVE_WANDDER
ETSISOURCES=format_etsilive.c format_etsifile.c format_etsi.h
else
ETSISOURCES=
endif

# Are we building with XDP support?
if HAVE_LIBBPF
XDP_SOURCES=format_linux_xdp.c format_linux_xdp.h

# are we building the XDP eBPF kernel program?
if BUILD_EBPF
format_linux_xdp_kern.bpf: format_linux_xdp_kern.c format_linux_xdp.h
	${CLANG} -Wall @CFLAGS@ -O2 \
		-I/usr/include \
                -fno-stack-protector \
		-D__KERNEL__ -D__ASM_SYSREG_H \
		-target bpf -S -emit-llvm $< -o ${@:.bpf=.ll}
	${LLC} -march=bpf -filetype=obj ${@:.bpf=.ll} -o $@
	${RM} ${@:.bpf=.ll}

EXTRA_DIST += format_linux_xdp_kern.c
endif

all: $(BPF_TARGETS)

else
XDP_SOURCES=
endif

# install libtrace bpf kern
xdpdir = $(datarootdir)/libtrace
xdp_DATA = format_linux_xdp_kern.bpf
EXTRA_DIST += format_linux_xdp_kern.bpf

if HAVE_PFRING
NATIVEFORMATS += format_pfring.c
endif

if HAVE_LINUX_ETHTOOL_H
LINUX_SOURCES += format_linux_helpers.c format_linux_helpers.h
endif


libtrace_la_SOURCES = trace.c trace_parallel.c common.h \
		format_pktmeta.c format_erf.c format_pcap.c format_legacy.c \
		format_rt.c format_helper.c format_helper.h format_pcapfile.c \
		$(XDP_SOURCES) \
		format_duck.c format_tsh.c $(NATIVEFORMATS) $(BPFFORMATS) \
		format_atmhdr.c format_pcapng.c format_tzsplive.c \
		libtrace_int.h lt_inttypes.h lt_bswap.h \
		linktypes.c link_wireless.c byteswap.c \
		checksum.c checksum.h \
		protocols_pktmeta.c protocols_l2.c protocols_l3.c \
		protocols_transport.c protocols.h protocols_ospf.c \
		protocols_application.c \
                protocols_radius.c libtrace_radius.h \
		$(DAGSOURCE) format_erf.h format_ndag.c format_ndag.h \
		$(BPFJITSOURCE) $(ETSISOURCES) \
		libtrace_arphrd.h $(LINUX_SOURCES) \
		data-struct/ring_buffer.c data-struct/vector.c \
		data-struct/message_queue.c data-struct/deque.c \
		data-struct/sliding_window.c data-struct/object_cache.c \
		data-struct/linked_list.c hash_toeplitz.c combiner_ordered.c \
                data-struct/buckets.c data-struct/simple_circular_buffer.c \
		combiner_sorted.c combiner_unordered.c \
		pthread_spinlock.c pthread_spinlock.h \
		strndup.c format_pcapng.h format_tzsplive.h

if DAG2_4
nodist_libtrace_la_SOURCES = dagopts.c dagapi.c
endif

AM_CPPFLAGS= @ADD_INCLS@
libtrace_la_LIBADD = @LIBTRACE_LIBS@ @LTLIBOBJS@ $(DPDKLIBS)
libtrace_la_LDFLAGS=-version-info 7:10:0 @ADD_LDFLAGS@
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
