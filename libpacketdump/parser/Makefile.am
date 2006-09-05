
noinst_LIBRARIES = libparser.a
libparser_a_SOURCES = lexer.l parser.y bitbuffer.c bitbuffer.h grammar.h
libparser_a_LIBADD = @ADD_LIBS@ 
libparser_a_LDFLAGS = @ADD_LDFLAGS@ -L../
INCLUDES = @ADD_INCLS@ -I../ -I../../lib

EXTRA_DIST=lexer.l parser.y
BUILT_SOURCES=parser.h
AM_YFLAGS=-d

