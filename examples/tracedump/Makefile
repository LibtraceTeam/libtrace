CXX=g++
INCLUDES=-I/usr/local/wand/include
CXXFLAGS=-g -Wall $(INCLUDES) -rdynamic
LDFLAGS=-L/usr/local/wand/lib
LDLIBS=-ltrace -ldl -lpcap -lz
LINK_LAYERS=$(addsuffix .so,$(basename $(wildcard link_*.cc)))
ETH_LAYERS=$(addsuffix .so,$(basename $(wildcard eth_*.cc)))
IP_LAYERS=$(addsuffix .so,$(basename $(wildcard ip_*.cc)))
TCP_LAYERS=$(addsuffix .so,$(basename $(wildcard tcp_*.cc)))
PLUGINS=$(LINK_LAYERS) $(ETH_LAYERS) $(IP_LAYERS) $(TCP_LAYERS)

all: tracedump $(PLUGINS) asn1-test

tracedump: tracedump.cc tracedump-libtrace.o tracedump-lib.o

tcp_1720.so: tcp_1720.cc asn1.o

%.so:%.cc
	$(CXX) $(CXXFLAGS) -fpic -shared $^ -o $@

asn1-test: CXXFLAGS+=-DTEST
asn1-test: asn1.cc

clean:
	rm -f *.o tracedump *.so

install:
	cp *.so $(LIBDIR)

.PHONY: clean all

