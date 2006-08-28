bin_PROGRAMS = tracedump
man_MANS = tracedump.1
EXTRA_DIST = $(man_MANS)

include ../Makefile.tools
tracedump_SOURCES = tracedump.cc
tracedump_LDADD = -ltrace -lpacketdump -lfl
