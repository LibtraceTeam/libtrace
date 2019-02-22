
RM=rm
PREFIX=../
CC=gcc

INCLUDE = -I$(PREFIX)/lib -I$(PREFIX)/libpacketdump
CFLAGS = -Wall -Wimplicit -Wformat -W -pedantic -pipe -g -O2 -std=gnu99 -pthread \
		-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CFLAGS += $(INCLUDE)
libdir = $(PREFIX)/lib/.libs:$(PREFIX)/libpacketdump/.libs
LDLIBS = -L$(PREFIX)/lib/.libs -L$(PREFIX)/libpacketdump/.libs -ltrace -lpacketdump

BINS_DATASTRUCT = test-datastruct-vector test-datastruct-deque \
	test-datastruct-ringbuffer
BINS_PARALLEL = test-format-parallel test-format-parallel-hasher \
	test-format-parallel-singlethreaded test-format-parallel-stressthreads \
	test-format-parallel-singlethreaded-hasher test-format-parallel-reporter test-tracetime-parallel

BINS = test-pcap-bpf test-event test-time test-dir test-wireless test-errors \
	test-plen test-autodetect test-ports test-fragment test-live \
	test-live-snaplen test-vxlan test-setcaplen test-wlen test-vlan \
	test-mpls test-layer2-headers test-qinq \
	$(BINS_DATASTRUCT) $(BINS_PARALLEL)

.PHONY: all clean distclean install depend test

all: $(BINS) test-drops test-format test-decode test-decode2 test-write test-convert test-convert2

clean:
	$(RM) $(BINS) $(OBJS) test-format test-decode test-convert \
	test-decode2 test-write test-drops test-convert2

distclean:
	$(RM) $(BINS) $(OBJS) test-format test-decode test-convert test-drops test-convert2

install:
	@true

# vim: noet ts=8 sw=8
