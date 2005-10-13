prefix=/home/perry/lib/libtrace

CFLAGS=-W -Wall -g -Os -I$(prefix)/include
LDFLAGS=-L$(prefix)/lib
LDLIBS=-ltrace

all: traceanon

traceanon: traceanon.o ipenc.o rijndael.o panon.o

clean:
	rm -f traceanon core *.o
