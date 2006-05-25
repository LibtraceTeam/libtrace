
PREFIX=../
CC=gcc

INCLUDE = -I$(PREFIX)/lib
CFLAGS = -Wall -Wimplicit -Wformat -pipe -g -O2 -D_FILE_OFFSET_BITS=64 \
		-D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CFLAGS += $(INCLUDE)
libdir = $(PREFIX)/lib/.libs
LDLIBS = -L$(libdir) -ltrace

BINS = test-pcap-bpf test-event test-time #test-seek 

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
	@for i in erf pcap wtf pcapfile duck; do			\
		echo \* $$i;					\
		LD_LIBRARY_PATH=$(libdir)			\
		./test-format $$i || exit $$?;			\
	done
	
test-convert-all: test-convert
# Not all types are convertable, for instance libtrace doesn't
# do rtclient output, and erf doesn't support 802.11
	@echo \* Conversions
	@echo " * erf -> erf"
	@LD_LIBRARY_PATH=$(libdir) ./test-convert erf erf
	@echo " * erf -> pcap"
	@LD_LIBRARY_PATH=$(libdir) ./test-convert erf pcap
	@echo " * pcap -> erf"
	@LD_LIBRARY_PATH=$(libdir) ./test-convert pcap erf
	@echo " * pcapfile -> erf"
	@LD_LIBRARY_PATH=$(libdir) ./test-convert pcapfile erf
	@#LD_LIBRARY_PATH=$(libdir) ./test-convert rtclient erf
	@#LD_LIBRARY_PATH=$(libdir) ./test-convert rtclient pcap
	@echo " * wtf -> pcap"
	@LD_LIBRARY_PATH=$(libdir) ./test-convert wtf pcap
	@echo " * wtf -> wtf"
	@LD_LIBRARY_PATH=$(libdir) ./test-convert wtf wtf
	@echo " * duck -> duck"
	@LD_LIBRARY_PATH=$(libdir) ./test-convert duck duck
 
clean:
	$(RM) $(BINS) $(OBJS) test-format

distclean:
	$(RM) $(BINS) $(OBJS) test-format

install:
	@true

# vim: noet ts=8 sw=8
