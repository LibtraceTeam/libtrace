
PREFIX=/usr/local/

#if using debian Woody, you probably want to use gcc-3.0 here
#CC=gcc-3.0
CC=gcc
CFLAGS= -Wall -Wimplicit -Wformat -pipe -g -O3

CFLAGS += -I../include -I$(PREFIX)/include
CFLAGS += -D_FILE_OFFSET_BITS=64
LDFLAGS = -L$(PREFIX)/lib/ -lpcap -lz


CURRENT=2
AGE=1
REVISION=0

.PHONY: all clean distclean install depend

all: libtrace.lo libtrace.la


libfifo.lo: 	fifo.c
	libtool --mode=compile $(CC) $(CFLAGS) -c $< -o libfifo.lo 

libtrace.lo: 	trace.c
	libtool --mode=compile $(CC) $(CFLAGS) -c $< -o libtrace.lo

libtrace.la:	libtrace.lo libfifo.lo
	libtool --mode=link $(CC) $(CFLAGS) -o libtrace.la \
	libtrace.lo libfifo.lo -rpath $(PREFIX)/lib $(LDFLAGS) \
	-version-info $(CURRENT):$(REVISION):$(AGE)


clean:
	$(RM) *~ *.o *.a *.lo *.la *.so .libs/*.*

distclean:
	$(RM) *~ *.o 


install-profile: libtrace-prof.la
	libtool --mode=install install -c libtrace-prof.la $(PREFIX)/lib/libtrace-prof.la
	libtool --finish $(PREFIX)/lib/

install: libtrace.la
	mkdir -p $(PREFIX)/lib
	libtool --mode=install install -c libtrace.la $(PREFIX)/lib/libtrace.la
	libtool --finish $(PREFIX)/lib/
	mkdir -p $(PREFIX)/include
	cp ../include/libtrace.h $(PREFIX)/include/libtrace.h
	cp ../include/dagformat.h $(PREFIX)/include/dagformat.h

docs:
	cd ..
	doxygen

# vim: noet ts=8 sw=8
