CXX=g++
INCLUDES=-I/usr/local/wand/include
CXXFLAGS=-g -Wall $(INCLUDES) -rdynamic
LDFLAGS=-L/usr/local/wand/lib
LDLIBS=-ltrace -ldl
LINK_LAYERS=$(addsuffix .so,$(basename $(wildcard link_*.cc)))
ETH_LAYERS=$(addsuffix .so,$(basename $(wildcard eth_*.cc)))
IP_LAYERS=$(addsuffix .so,$(basename $(wildcard ip_*.cc)))
PLUGINS=$(LINK_LAYERS) $(ETH_LAYERS) $(IP_LAYERS)

all: tracedump $(PLUGINS)

tracedump: tracedump.cc tracedump-libtrace.o tracedump-lib.o

%.so:%.cc
	$(CXX) $(CXXFLAGS) -fpic -shared $< -o $@

clean:
	rm -f *.o tracedump *.so

.PHONY: clean all

