CFLAGS=-g -Wall -I/usr/include/python2.1 -I../include -I /usr/lib/perl/5.8.4/CORE/
LDDIRS=-L../lib
LDLIBS=-ltrace -lpcap -lz

all: 	libtrace_wrap.o
	gcc -shared libtrace_wrap.o $(LDDIRS) $(LDLIBS) -o _libtrace.so

libtrace_wrap.o: libtrace_wrap.c

libtrace_wrap.c: libtrace.i
	swig -python libtrace.i


clean:
	rm -f libtrace_wrap.c libtrace_wrap.o _libtrace.so
