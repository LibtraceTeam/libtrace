
wand_include = /usr/local/wand/include
wand_libs = /usr/local/wand/lib

CC=gcc-3.0

INCLUDE = -I../include -I$(wand_include)
CFLAGS = -Wall -Wimplicit -Wformat -pipe -g -O2
CFLAGS += $(INCLUDE)
libdir = -L$(wand_libs)
LDLIBS = $(libdir) -ltrace

BINS = protocol
.PHONY: all clean distclean install depend

all: $(BINS) 

clean:
	$(RM) *~ *.o $(BINS) $(OBJS) core

distclean:
	$(RM) *~ *.o $(BINS) $(OBJS) core

install:
	@true


# vim: noet ts=8 sw=8
