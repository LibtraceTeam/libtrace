
PREFIX=../
CC=gcc

INCLUDE = -I$(PREFIX)/lib -I$(PREFIX)/libpacketdump
CFLAGS = -Wall -Wimplicit -Wformat -W -pedantic -pipe -g -O2 
		-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CFLAGS += $(INCLUDE)
libdir = $(PREFIX)/lib/.libs:$(PREFIX)/libpacketdump/.libs
LDLIBS = -L$(PREFIX)/lib/.libs -L$(PREFIX)/libpacketdump/.libs -ltrace -lpacketdump -lfl

BINS = test-pcap-bpf test-event test-time test-dir test-wireless #test-seek 

.PHONY: all clean distclean install depend test

all: $(BINS) 

test: all test-format-all test-convert-all test-write-all test-programs

test-programs: $(BINS)
	@for i in $(BINS); do					\
		echo \* $$i; 					\
		rm -f traces/*.out.*;				\
		LD_LIBRARY_PATH="$(libdir)"			\
		 ./$$i || exit $$?;				\
	done				
	@echo All tests passed

test-format-all: test-format test-decode test-decode2
	@for i in erf pcap wtf pcapfile duck; do		\
		echo \* Read $$i;				\
		rm -f traces/*.out.*;				\
		LD_LIBRARY_PATH="$(libdir)"			\
		./test-format $$i || exit $$?;			\
		LD_LIBRARY_PATH="$(libdir)"			\
		./test-decode $$i || exit $$?;			\
	done
# Try various link layer decodes
	# SLL Decoder 
	@LD_LIBRARY_PATH="$(libdir)" \
	./test-decode2 pcap:traces/100_sll.pcap

	# 802.1x decoder
	@LD_LIBRARY_PATH="$(libdir)" \
	./test-decode2 pcap:traces/8021x.pcap

	# MPLS Decoder
	@LD_LIBRARY_PATH="$(libdir)" \
	./test-decode2 pcap:traces/10_mpls_ip.pcap

	# Radius Decoder
	@LD_LIBRARY_PATH="$(libdir)" \
	./test-decode2 pcap:traces/radius.pcap

test-write-all: test-write
	@for i in erf pcap; do					\
		echo \* Write $$i;				\
		rm -f traces/*.out.*;				\
		LD_LIBRARY_PATH="$(libdir)"			\
		./test-write $$i || exit $$?; 			\
	done
	
test-convert-all: test-convert
# Not all types are convertable, for instance libtrace doesn't
# do rtclient output, and erf doesn't support 802.11
	@echo \* Conversions
	@echo " * erf -> erf"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" ./test-convert erf erf
	@echo " * erf -> pcap"
	@LD_LIBRARY_PATH="$(libdir)" ./test-convert erf pcap
	@echo " * pcap -> erf"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" ./test-convert pcap erf
	@echo " * pcapfile -> erf"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" ./test-convert pcapfile erf
	@echo " * pcapfile -> pcapfile"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" ./test-convert pcapfile pcapfile
	@echo " * pcap -> pcapfile"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" ./test-convert pcap pcapfile
	@echo " * erf -> pcapfile"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" ./test-convert erf pcapfile
	@#LD_LIBRARY_PATH="$(libdir)" ./test-convert rtclient erf
	@#LD_LIBRARY_PATH="$(libdir)" ./test-convert rtclient pcap
	@echo " * wtf -> pcap"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" ./test-convert wtf pcap
	@echo " * wtf -> wtf"
	#@rm -f traces/*.out.*
	#@LD_LIBRARY_PATH="$(libdir)" ./test-convert wtf wtf
	@echo " * duck -> duck"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" ./test-convert duck duck
 
clean:
	$(RM) $(BINS) $(OBJS) test-format  test-decode test-convert

distclean:
	$(RM) $(BINS) $(OBJS) test-format test-decode test-convert

install:
	@true

# vim: noet ts=8 sw=8
