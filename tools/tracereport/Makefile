
PREFIX=/usr/local
CC=gcc

INCLUDE = -I$(PREFIX)/include
CFLAGS = -Wall -Wimplicit -Wformat -pipe -g -O2
CFLAGS += $(INCLUDE)
libdir = -L$(PREFIX)/lib
LDLIBS = $(libdir) -ltrace

BINS = tracereport 
.PHONY: all clean distclean install depend

all: $(BINS) 

tracereport: tracereport.o \
	tree.o \
	port_report.o tos_report.o protocol_report.o error_report.o \
	ttl_report.o flow_report.o

clean:
	$(RM) $(BINS) $(OBJS) core *.o

distclean:
	$(RM) $(BINS) $(OBJS)  core *.o

install:
	@true


# vim: noet ts=8 sw=8
