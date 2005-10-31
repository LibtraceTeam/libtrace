CXX=g++
PREFIX?=/usr/local
INCLUDES=-I$(PREFIX)/include
# Directory to search for plugins
LIBDIR="./"
CXXFLAGS=-g -Wall $(INCLUDES) -rdynamic
LDFLAGS=-L$(PREFIX)/lib
LDLIBS=-ltrace -ldl -lpacketdump

all: tracedump 

%.so:%.cc
	$(CXX) $(CXXFLAGS) -fpic -shared $^ -o $@


clean:
	rm -f *.o tracedump *.so

install:
	cp *.so $(LIBDIR)

.PHONY: clean all links

