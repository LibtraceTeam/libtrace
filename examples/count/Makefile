
PREFIX=/usr/local
CC=gcc

INCLUDE = -I$(PREFIX)/include
CFLAGS = -Wall -Wimplicit -Wformat -pipe -g -O2
CFLAGS += $(INCLUDE)
libdir = -L$(PREFIX)/lib
LDLIBS = $(libdir) -ltrace

BINS = count 
.PHONY: all clean distclean install depend

all: $(BINS) 

clean:
	$(RM) $(BINS) $(OBJS) 

distclean:
	$(RM) $(BINS) $(OBJS) 

install:
	@true


# vim: noet ts=8 sw=8
