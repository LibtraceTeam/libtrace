CC=gcc-3.0
CFLAGS= -Wall -Wimplicit -Wformat -pipe -g -O3

INCLUDE = -I../include -I/usr/local/wand/include
CFLAGS += -D_FILE_OFFSET_BITS=64
CFLAGS += $(INCLUDE)
libdir = -L/usr/local/wand/lib/
LDLIBS = $(libdir) -lpcapl -lzl


CURRENT=1
AGE=0
REVISION=8

INCLIBS=/usr/local/wand/lib/libzl.a /usr/local/wand/lib/libpcapl.a

.PHONY: all clean distclean install depend

all: libtrace.lo libtrace.la


libfifo.lo: 	fifo.c
	libtool --mode=compile $(CC) $(CFLAGS) -c $< -o libfifo.lo 

libtrace.lo: 	trace.c
	libtool --mode=compile $(CC) $(CFLAGS) -c $< -o libtrace.lo

libtrace.la:	libtrace.lo libfifo.lo
	libtool --mode=link $(CC) $(CFLAGS) -o libtrace.la \
	libtrace.lo libfifo.lo -rpath /usr/local/wand/lib $(LDLIBS) \
	-version-info $(CURRENT):$(REVISION):$(AGE)


clean:
	$(RM) *~ *.o libtrace.a *.lo *.la libtrace.so.* .libs/*.*

distclean:
	$(RM) *~ *.o 


install: libtrace.la
	libtool --mode=install install -c libtrace.la /usr/local/wand/lib/libtrace.la
	libtool --finish /usr/local/wand/lib/
	cp ../include/libtrace.h /usr/local/wand/include/libtrace.h

# vim: noet ts=8 sw=8
