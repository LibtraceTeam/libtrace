CC=gcc-3.0
CFLAGS= -Wall -Wimplicit -Wformat -pipe -g -O3

INCLUDE = -I../include -I/usr/local/wand/include
CFLAGS += -D_FILE_OFFSET_BITS=64
CFLAGS += $(INCLUDE)
LDFLAGS = -L/usr/local/wand/lib/
LDLIBS = $(LDFLAGS) -lpcapl -lzl


LIBRT=libtrace.so
LIBRTM=libtrace.so.1
LIBRTV=libtrace.so.1.0.6

INCLIBS=/usr/local/wand/lib/libzl.a /usr/local/wand/lib/libpcapl.a

.PHONY: all clean distclean install depend

all: libtrace.lo libtrace.la


libfifo.lo: 	fifo.c
	libtool --mode=compile $(CC) $(CFLAGS) -c $< -o libfifo.lo 

libtrace.lo: 	trace.c
	libtool --mode=compile $(CC) $(CFLAGS) -c $< -o libtrace.lo

libtrace.la:	libtrace.lo libfifo.lo
	libtool --mode=link $(CC) $(CFLAGS) -o libtrace.la libtrace.lo libfifo.lo -rpath /usr/local/wand/lib $(LDLIBS)

libtrace.so: trace.o fifo.o 
	gcc -shared -Wl,-soname,$(LIBRTM) -o $(LIBRTV) $^ $(INCLIBS) $(LDFLAGS) 

libtrace.a: libtrace.a(trace.o) libtrace.a(fifo.o)


clean:
	$(RM) *~ *.o libtrace.a *.lo *.la libtrace.so.* .libs/*

distclean:
	$(RM) *~ *.o 

#install:
#	@true

#install-libtrace: libtrace.a libtrace.so
#	cp libtrace.a /usr/local/wand/lib
#	cp $(LIBRTV) /usr/local/wand/lib
#	cp ../include/libtrace.h /usr/local/wand/include/libtrace.h
#	ldconfig

install: libtrace.la
	libtool --mode=install install -c libtrace.la /usr/local/wand/lib/libtrace.la
	libtool --finish /usr/local/wand/lib/
	cp ../include/libtrace.h /usr/local/wand/include/libtrace.h
#libtool --mode=install install -c libtrace.la /usr/local/wand/lib/libtrace.la
#libtool --finish /usr/local/wand/lib/

# vim: noet ts=8 sw=8
