
PREFIX=/usr/local
CC=gcc

INCLUDE = -I$(PREFIX)/include
CFLAGS = -Wall -Wimplicit -Wformat -pipe -g -O2 -D_FILE_OFFSET_BITES=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CFLAGS += $(INCLUDE)
libdir = -L$(PREFIX)/lib
LDLIBS = $(libdir) -ltrace -lzl

BINS = capture capture-gzip
.PHONY: all clean distclean install depend

all: $(BINS) 

clean:
	$(RM) *~ *.o $(BINS) $(OBJS) core

distclean:
	$(RM) *~ *.o $(BINS) $(OBJS) core

install:
	@true


# vim: noet ts=8 sw=8
