bin_PROGRAMS = tracepktdump
man_MANS = tracepktdump.1
EXTRA_DIST = $(man_MANS)

include ../Makefile.tools
tracepktdump_SOURCES = tracepktdump.cc
tracepktdump_LDADD = -ltrace -lpacketdump 
