lib_LTLIBRARIES = libparser.la
#include_HEADERS = parser.h

libparser_la_SOURCES = lexer.l parser.y bitbuffer.c bitbuffer.h grammar.h
libparser_la_LIBADD = @ADD_LIBS@ @LEXLIB@
libparser_la_LDFLAGS = @ADD_LDFLAGS@ -L../  -version-info @LIBTRACE_MAJOR@:@LIBTRACE_MINOR@:@LIBTRACE_MID@	
INCLUDES = @ADD_INCLS@ -I../ -I../../lib

EXTRA_DIST=lexer.l parser.y
BUILT_SOURCES=parser.h
AM_YFLAGS=-d

