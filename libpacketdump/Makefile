CXX=g++
LD=g++
PREFIX?=/usr/local
INCLUDES=-I$(PREFIX)/include
# Directory to search for plugins
LIBDIR=\"$(shell pwd)\"
CXXFLAGS=-g -Wall -DDIRNAME=$(LIBDIR) $(INCLUDES) -rdynamic
CFLAGS=-g -Wall $(INCLUDES) -rdynamic
LDFLAGS=-L$(PREFIX)/lib -rdynamic
LDLIBS=-ltrace -ldl 
LINK_LAYERS=$(addsuffix .so,$(basename $(wildcard link_*.cc)))
ETH_LAYERS=$(addsuffix .so,$(basename $(wildcard eth_*.cc)))
IP_LAYERS=$(addsuffix .so,$(basename $(wildcard ip_*.cc)))
TCP_LAYERS=$(addsuffix .so,$(basename $(wildcard tcp_*.cc)))
PLUGINS=$(LINK_LAYERS) $(ETH_LAYERS) $(IP_LAYERS) $(TCP_LAYERS)

all: libpacketdump.so $(PLUGINS)

tcp_1720.so: 

%.so:%.cc
	$(CXX) $(CXXFLAGS) -fpic -shared $^ -o $@

asn1-test: CXXFLAGS+=-DTEST
asn1-test: asn1.cc
	$(CXX) $(CXXFLAGS) $^ -o $@

links: links.txt
	./make_links

clean:
	rm -f *.o testprocess *.so

install:
	cp *.so $(LIBDIR)

.PHONY: clean all links

