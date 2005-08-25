prefix=/usr/include

CFLAGS=-W -Wall -g -I$(prefix)/include
LDLIBS=-ltrace lib/libtrace_enc.a
LDFLAGS=-L$(prefix)/lib -L/tmp/lib

all: munge

clean:
	rm -f munge core 
