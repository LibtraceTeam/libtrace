bin_PROGRAMS = traceanon

man_MANS = traceanon.1
EXTRA_DIST = $(man_MANS)

include ../Makefile.tools
traceanon_SOURCES = traceanon.c rijndael.h rijndael.c panon.h panon.c ipenc.c ipenc.h 

# rijndael.c does lots of nasty casting that is going to be a nightmare to fix
# and debug - I'm going to disable this warning in the interim, as it's really
# messy and hopefully isn't actually an issue. 
traceanon_CFLAGS = $(AM_CFLAGS)
