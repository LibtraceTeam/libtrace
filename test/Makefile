
PREFIX=../
CC=gcc

INCLUDE = -I$(PREFIX)/lib -I$(PREFIX)/libpacketdump
CFLAGS = -Wall -Wimplicit -Wformat -W -pedantic -pipe -g -O2 
		-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CFLAGS += $(INCLUDE)
libdir = $(PREFIX)/lib/.libs:$(PREFIX)/libpacketdump/.libs
LDLIBS = -L$(PREFIX)/lib/.libs -L$(PREFIX)/libpacketdump/.libs -ltrace -lpacketdump -lfl

BINS = test-pcap-bpf test-event test-time test-dir test-wireless test-errors 
	#test-seek 

.PHONY: all clean distclean install depend test

all: $(BINS) 

test: all test-format-all test-convert-all test-write-all test-programs

test-programs: $(BINS)
	@for i in $(BINS); do					\
		echo \* $$i; 					\
		rm -f traces/*.out.*;				\
		LD_LIBRARY_PATH="$(libdir)"			\
		DYLD_LIBRARY_PATH="$(libdir)"			\
		 ./$$i || exit $$?;				\
	done				
	@echo All tests passed

test-format-all: test-format test-decode test-decode2
# Try various link layer decodes
	@echo SLL Decoder 
	@LD_LIBRARY_PATH="$(libdir)" \
	DYLD_LIBRARY_PATH="$(libdir)" \
	./test-decode2 pcap:traces/100_sll.pcap

	@echo 802.1x decoder
	@LD_LIBRARY_PATH="$(libdir)" \
	DYLD_LIBRARY_PATH="$(libdir)" \
	./test-decode2 pcap:traces/8021x.pcap

	@echo MPLS Decoder
	@LD_LIBRARY_PATH="$(libdir)" \
	DYLD_LIBRARY_PATH="$(libdir)" \
	./test-decode2 pcap:traces/10_mpls_ip.pcap

	@echo Radius Decoder
	@LD_LIBRARY_PATH="$(libdir)" \
	DYLD_LIBRARY_PATH="$(libdir)" \
	./test-decode2 pcap:traces/radius.pcap
	@for i in erf pcap pcapfile duck legacyatm legacyeth legacypos tsh;\
	do \
		echo \* Read $$i;				\
		rm -f traces/*.out.*;				\
		LD_LIBRARY_PATH="$(libdir)"			\
		DYLD_LIBRARY_PATH="$(libdir)" 			\
		./test-format $$i || exit $$?;			\
		LD_LIBRARY_PATH="$(libdir)"			\
		DYLD_LIBRARY_PATH="$(libdir)" 			\
		./test-decode $$i || exit $$?;			\
	done

test-write-all: test-write
	@for i in erf pcap pcapfile; do				\
		echo \* Write $$i;				\
		rm -f traces/*.out.*;				\
		LD_LIBRARY_PATH="$(libdir)"			\
		DYLD_LIBRARY_PATH="$(libdir)" 			\
		./test-write $$i || exit $$?; 			\
	done
	
test-convert-all: test-convert
# Not all types are convertable, for instance libtrace doesn't
# do rtclient output, and erf doesn't support 802.11
	@echo \* Conversions
	@echo " * erf -> erf"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" DYLD_LIBRARY_PATH="$(libdir)" ./test-convert erf erf
	@echo " * erf -> pcap"
	@LD_LIBRARY_PATH="$(libdir)" DYLD_LIBRARY_PATH="$(libdir)" ./test-convert erf pcap
	@echo " * pcap -> erf"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" DYLD_LIBRARY_PATH="$(libdir)" ./test-convert pcap erf
	@echo " * pcapfile -> erf"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" DYLD_LIBRARY_PATH="$(libdir)" ./test-convert pcapfile erf
	@echo " * pcapfile -> pcapfile"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" DYLD_LIBRARY_PATH="$(libdir)" ./test-convert pcapfile pcapfile
	@echo " * pcap -> pcapfile"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" DYLD_LIBRARY_PATH="$(libdir)" ./test-convert pcap pcapfile
	@echo " * erf -> pcapfile"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" DYLD_LIBRARY_PATH="$(libdir)" ./test-convert erf pcapfile
	@#LD_LIBRARY_PATH="$(libdir)" DYLD_LIBRARY_PATH="$(libdir)" ./test-convert rtclient erf
	@#LD_LIBRARY_PATH="$(libdir)" DYLD_LIBRARY_PATH="$(libdir)" ./test-convert rtclient pcap

	@# This doesn't work because pcap doesn't support legacyatm's linketype
	@# so the packet is converted to a raw IP packet, which when read
	@# back in again doesn't match legacyatm's original packet.
	@#echo " * legacyatm -> pcapfile"
	@#rm -f traces/*.out.*
	@#LD_LIBRARY_PATH="$(libdir)" DYLD_LIBRARY_PATH="$(libdir)" ./test-convert legacyatm pcapfile

	@echo " * legacyeth -> pcapfile"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" DYLD_LIBRARY_PATH="$(libdir)" ./test-convert legacyeth pcapfile

	@echo " * legacypos -> pcapfile"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" DYLD_LIBRARY_PATH="$(libdir)" ./test-convert legacypos pcapfile

	@echo " * duck -> duck"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" DYLD_LIBRARY_PATH="$(libdir)" ./test-convert duck duck

	@echo " * tsh -> pcapfile"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" DYLD_LIBRARY_PATH="$(libdir)" ./test-convert tsh pcapfile
	@echo " * tsh -> pcap"
	@rm -f traces/*.out.*
	@LD_LIBRARY_PATH="$(libdir)" DYLD_LIBRARY_PATH="$(libdir)" ./test-convert tsh pcap
 
clean:
	$(RM) $(BINS) $(OBJS) test-format  test-decode test-convert \
	test-decode2 test-write

distclean:
	$(RM) $(BINS) $(OBJS) test-format test-decode test-convert

install:
	@true

# vim: noet ts=8 sw=8
