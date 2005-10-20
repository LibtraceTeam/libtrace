CXX=g++
PREFIX?=/usr/local
INCLUDES=-I$(PREFIX)/include
# Directory to search for plugins
LIBDIR="./"
CXXFLAGS=-g -Wall $(INCLUDES) -rdynamic
LDFLAGS=-L$(PREFIX)/lib
LDLIBS=-ltrace -ldl 
LINK_LAYERS=$(addsuffix .so,$(basename $(wildcard link_*.cc)))
ETH_LAYERS=$(addsuffix .so,$(basename $(wildcard eth_*.cc)))
IP_LAYERS=$(addsuffix .so,$(basename $(wildcard ip_*.cc)))
TCP_LAYERS=$(addsuffix .so,$(basename $(wildcard tcp_*.cc)))
PLUGINS=$(LINK_LAYERS) $(ETH_LAYERS) $(IP_LAYERS) $(TCP_LAYERS)

all: tracedump $(PLUGINS) links

tracedump: tracedump.cc tracedump-libtrace.o tracedump-lib.o

tracedump-lib.o: CXXFLAGS+=-DLIBDIR=$(LIBDIR)

tcp_1720.so: 

%.so:%.cc
	$(CXX) $(CXXFLAGS) -fpic -shared $^ -o $@

asn1-test: CXXFLAGS+=-DTEST
asn1-test: asn1.cc
	$(CXX) $(CXXFLAGS) $^ -o $@

links: links.txt
	./make_links

clean:
	rm -f *.o tracedump *.so

install:
	cp *.so $(LIBDIR)

.PHONY: clean all links

