
PREFIX=../
CC=gcc

INCLUDE = -I$(PREFIX)/lib
CFLAGS = -Wall -Wimplicit -Wformat -pipe -g -O2 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CFLAGS += $(INCLUDE)
libdir = $(PREFIX)/lib/.libs
LDLIBS = -L$(libdir) -ltrace

BINS = test1 test2 test-pcap test-pcap-bpf test-erf-write test-erf-to-pcap \
	test-pcap-to-erf test-wtf test-rtclient test-event
.PHONY: all clean distclean install depend test

all: $(BINS) 

test: all
	for i in $(BINS); do					\
		echo \* $$i; 					\
		LD_LIBRARY_PATH=$(libdir)			\
		 ./$$i || exit $$?;				\
	done				
 
clean:
	$(RM) $(BINS) $(OBJS) 

distclean:
	$(RM) $(BINS) $(OBJS) 

install:
	@true


# vim: noet ts=8 sw=8
