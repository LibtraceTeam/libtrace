
PREFIX?=/usr/local
CC=gcc

INCLUDE = -I$(PREFIX)/include -I../../libpacketdump
CFLAGS = -Wall -Wimplicit -Wformat -pipe -g -O2
CFLAGS += $(INCLUDE)
libdir = -L$(PREFIX)/lib -L../../libpacketdump
LDLIBS = $(libdir) -ltrace -lpacketdump -ldl

BINS = tracedump 
.PHONY: all clean distclean install depend

all: $(BINS) 

clean:
	$(RM) $(BINS) $(OBJS) core *.o

distclean:
	$(RM) $(BINS) $(OBJS)  core *.o

install:
	@true


# vim: noet ts=8 sw=8
