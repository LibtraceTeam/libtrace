
PREFIX=/usr/local
CC=gcc

INCLUDE = -I$(PREFIX)/include
CFLAGS = -Wall -Wimplicit -Wformat -pipe -g -O2
CFLAGS += $(INCLUDE)
libdir = -L$(PREFIX)/lib
LDLIBS = $(libdir) -ltrace -lgdc

BINS = tracertstats
.PHONY: all clean distclean install depend

all: $(BINS) 

tracertstats: tracertstats.o \
		output.o \
		output_csv.o output_html.o output_png.o

clean:
	$(RM) $(BINS) $(OBJS) core *.o

distclean:
	$(RM) $(BINS) $(OBJS) core *.o

install:
	@true


# vim: noet ts=8 sw=8
