if HAVE_YAML
bin_PROGRAMS = traceanon 

man_MANS = traceanon.1
EXTRA_DIST = $(man_MANS)

include ../Makefile.tools
#traceanon_SOURCES = traceanon.c rijndael.h rijndael.c panon.h panon.c ipenc.c ipenc.h 
traceanon_SOURCES = traceanon.cc Anon.cc Anon.h ../tools_yaml.c \
        ../tools_yaml.h traceanon_config.c traceanon.h

# Stupid Apple decided to deprecate the low-level OpenSSL EVP functions
traceanon_CPPFLAGS = $(AM_CPPFLAGS) -Wno-deprecated-declarations
endif
