
CC=gcc

CFLAGS = -Wall -Wimplicit -Wformat -pipe -O2 -fPIC -g 
CFLAGS += -I ../../../ -I/tmp/include
LDFLAGS = -L/tmp/lib -L/usr/local/lib -L.

BINS = libtrace_enc.a test-enc
.PHONY: all clean distclean install depend

all: $(BINS) 

clean:
	$(RM) *~ *.o $(BINS) $(OBJS) core

distclean:
	$(RM) *~ *.o $(BINS) $(OBJS) core

install:
	@true


libtrace_enc.a: libtrace_enc.a(libtrace_enc.o) \
		libtrace_enc.a(panon.o) \
		libtrace_enc.a(rijndael.o)

test-enc: LDLIBS=libtrace_enc.a
test-enc: libtrace_enc.o test-enc.c


# vim: noet ts=8 sw=8
