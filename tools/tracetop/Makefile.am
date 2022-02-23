if HAVE_NCURSES
man_MANS = tracetop.1
EXTRA_DIST = $(man_MANS)
bin_PROGRAMS = tracetop

include ../Makefile.tools

tracetop_SOURCES = tracetop.cc
tracetop_LDADD = @ncurses_LIBS@
tracetop_CPPFLAGS = -fno-strict-aliasing $(AM_CFLAGS)
endif
