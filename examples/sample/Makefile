
PREFIX=/usr/local
CC=gcc

INCLUDE = -I$(PREFIX)/include
CFLAGS = -Wall -Wimplicit -Wformat -pipe -g -O2 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CFLAGS += $(INCLUDE)
libdir = -L$(PREFIX)/lib
LDLIBS = $(libdir) -ltrace

BINS = sample
.PHONY: all clean distclean install depend

all: $(BINS) 

clean:
	$(RM) $(BINS) $(OBJS) 

distclean:
	$(RM) $(BINS) $(OBJS) 

install:
	@true


# vim: noet ts=8 sw=8
