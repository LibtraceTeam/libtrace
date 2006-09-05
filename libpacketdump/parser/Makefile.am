
# This library isn't installed, it is just a temporary file as part
# of the build process, therefore it needs no version informatino
noinst_LIBRARIES = libparser.a
libparser_a_SOURCES = lexer.l parser.y bitbuffer.c bitbuffer.h grammar.h
libparser_a_LIBADD = @ADD_LIBS@ 
INCLUDES = @ADD_INCLS@ -I../ -I../../lib

EXTRA_DIST=lexer.l parser.y
BUILT_SOURCES=parser.h
AM_YFLAGS=-d

