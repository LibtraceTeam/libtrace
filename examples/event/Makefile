
PREFIX=/usr/local
CC=gcc

INCLUDE = -I/home/dlawson/code/libtrace/lib/
CFLAGS = -Wall -Wimplicit -Wformat -pipe -g -O2
CFLAGS += $(INCLUDE)
libdir = -L/home/dlawson/code/libtrace/lib/.libs/
LDLIBS = $(libdir) -lpcap -lz

BINS = rate rate-tracetime
.PHONY: all clean distclean install depend

all: $(BINS) 

rate: rate.c ../../lib/.libs/libtrace.a

rate-tracetime: rate-tracetime.c ../../lib/.libs/libtrace.a

clean:
	$(RM) *~ *.o $(BINS) $(OBJS) core

distclean:
	$(RM) *~ *.o $(BINS) $(OBJS) core

install:
	@true


# vim: noet ts=8 sw=8
