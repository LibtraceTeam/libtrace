
PREFIX=../
CC=gcc

INCLUDE = -I$(PREFIX)/lib
CFLAGS = -Wall -Wimplicit -Wformat -pipe -g -O2 -D_FILE_OFFSET_BITS=64 \
		-D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CFLAGS += $(INCLUDE)
libdir = $(PREFIX)/lib/.libs
LDLIBS = -L$(libdir) -ltrace

BINS = test-pcap-bpf test-event test-time test-seek 

.PHONY: all clean distclean install depend test

all: $(BINS) 

test: all test-format-all test-convert-all		
	@for i in $(BINS); do					\
		echo \* $$i; 					\
		LD_LIBRARY_PATH=$(libdir)			\
		 ./$$i || exit $$?;				\
	done				
	@echo All tests passed

test-format-all: test-format
	@for i in erf pcap wtf ; do			\
		echo \* $$i;					\
		./test-format $$i || exit $$?;			\
	done
	
test-convert-all: test-convert
	@for i in erf pcap wtf rtclient; do			\
		for j in erf pcap ; do				\
			echo \* $$i -\> $$j;			\
			./test-convert $$i $$j || exit $$?;	\
		done;						\
	done							
	./test-convert wtf wtf

 
clean:
	$(RM) $(BINS) $(OBJS) 

distclean:
	$(RM) $(BINS) $(OBJS) 

install:
	@true

# vim: noet ts=8 sw=8
