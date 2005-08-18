
PREFIX=../
CC=gcc

INCLUDE = -I$(PREFIX)/lib
CFLAGS = -Wall -Wimplicit -Wformat -pipe -g -O2 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CFLAGS += $(INCLUDE)
libdir = $(PREFIX)/lib/.libs
LDLIBS = -L$(libdir) -ltrace

BINS = test1
.PHONY: all clean distclean install depend

all: $(BINS) 
 
clean:
	$(RM) $(BINS) $(OBJS) 

distclean:
	$(RM) $(BINS) $(OBJS) 

install:
	@true


# vim: noet ts=8 sw=8
