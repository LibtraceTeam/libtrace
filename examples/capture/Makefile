
PREFIX=/usr/local
CC=gcc

INCLUDE = -I$(PREFIX)/include
CFLAGS = -Wall -Wimplicit -Wformat -pipe -g -O2 -D_FILE_OFFSET_BITES=64
CFLAGS += $(INCLUDE)
libdir = -L$(PREFIX)/lib
LDLIBS = $(libdir) -ltrace

BINS = capture
.PHONY: all clean distclean install depend

all: $(BINS) 

clean:
	$(RM) *~ *.o $(BINS) $(OBJS) core

distclean:
	$(RM) *~ *.o $(BINS) $(OBJS) core

install:
	@true


# vim: noet ts=8 sw=8
