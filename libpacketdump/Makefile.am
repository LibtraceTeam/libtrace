lib_LTLIBRARIES = libpacketdump.la
include_HEADERS = libpacketdump.h 

#LINK_LAYERS=$(addsuffix .so,$(basename $(wildcard link_*.cc)))
#ETH_LAYERS=$(addsuffix .so,$(basename $(wildcard eth_*.cc)))
#IP_LAYERS=$(addsuffix .so,$(basename $(wildcard ip_*.cc)))
#TCP_LAYERS=$(addsuffix .so,$(basename $(wildcard tcp_*.cc)))

LINK_LAYERS=$(wildcard link_*.cc)
ETH_LAYERS=$(wildcard eth_*.cc)
IP_LAYERS=$(wildcard ip_*.cc)
TCP_LAYERS=$(wildcard tcp_*.cc)

PLUGINSOURCES=$(LINK_LAYERS) $(ETH_LAYERS) $(IP_LAYERS) $(TCP_LAYERS)
PLUGINS=$(addsuffix .so,$(basename $(PLUGINSOURCES)))

libpacketdump_la_SOURCES = libpacketdump.cc $(PLUGINSOURCES)

PLUGINDIR=$(libdir)/libpacketdump

INCLUDES= @ADD_INCLS@ -I../lib -I../
libpacketdump_la_LIBADD = @ADD_LIBS@  
libpacketdump_la_LDFLAGS=-version-info 2:23:0 @ADD_LDFLAGS@

AM_CXXFLAGS=-g -Wall -DDIRNAME=\"$(PLUGINDIR)\" -rdynamic $(INCLUDES)



%.so: %.cc
	$(CXX) $(AM_CXXFLAGS) -fpic -shared $^ -o $@

all-local: $(PLUGINS)
	
clean-local: 
	rm -f $(PLUGINS)

install-exec-local:
	for plugin in $(PLUGINS); do install -D -m 755 $$plugin $(PLUGINDIR)/$$plugin; done
