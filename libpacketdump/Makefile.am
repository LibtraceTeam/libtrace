lib_LTLIBRARIES = libpacketdump.la
include_HEADERS = libpacketdump.h 

LINK_LAYERS=$(wildcard link_*.cc)
ETH_LAYERS=$(wildcard eth_*.cc)
IP_LAYERS=$(wildcard ip_*.cc)
TCP_LAYERS=$(wildcard tcp_*.cc)
TEXT_PROTOCOLS=$(wildcard *.protocol)

PLUGINSOURCES=$(LINK_LAYERS) $(ETH_LAYERS) $(IP_LAYERS) $(TCP_LAYERS)
PLUGINS=$(addsuffix .so,$(basename $(PLUGINSOURCES))) 
ALLPLUGINS=$(PLUGINS) $(TEXT_PROTOCOLS)

SUBDIRS = parser

libpacketdump_la_SOURCES = libpacketdump.cc $(PLUGINSOURCES)

PLUGINDIR=$(libdir)/libpacketdump

INCLUDES= @ADD_INCLS@ -I../lib -I../
libpacketdump_la_LIBADD = @ADD_LIBS@ -lparser
libpacketdump_la_LDFLAGS=\
	-version-info @LIBTRACE_MAJOR@:@LIBTRACE_MINOR@:@LIBTRACE_MID@ \
	@ADD_LDFLAGS@ \
	-L./parser

AM_CXXFLAGS=-g -Wall -DDIRNAME=\"$(PLUGINDIR)\" -rdynamic $(INCLUDES)



%.so: %.cc
	$(CXX) $(AM_CXXFLAGS) -fpic -shared $^ -o $@

all-local: $(ALLPLUGINS)
	
clean-local: 
	rm -f $(PLUGINS)

install-exec-local:
	mkdir -p $(DESTDIR)$(PLUGINDIR); for plugin in $(ALLPLUGINS); do install -m 755 $$plugin $(DESTDIR)$(PLUGINDIR)/$$plugin; done

uninstall-local:
	for plugin in $(PLUGINS); do rm -f $(PLUGINDIR)/$$plugin; done
	rmdir $(PLUGINDIR)
