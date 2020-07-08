bin_PROGRAMS = tracediff
bin_PROGRAMS = tracediff2

man_MANS = tracediff.1
EXTRA_DIST = $(man_MANS)

include ../Makefile.tools

tracediff_SOURCES = tracediff.c
tracediff_LDADD = -lpacketdump

tracediff2_SOURCES = tracediff2.c
tracediff2_LDADD = -lpacketdump
