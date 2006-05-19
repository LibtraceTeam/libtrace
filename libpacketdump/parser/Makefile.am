lib_LTLIBRARIES = libparser.la
#include_HEADERS = parser.h

#libparser_la_SOURCES = libconfig.c libconfig.h config_internal.h config.lexer.c config.parser.h configuration.h config.parser.c
libparser_la_SOURCES = parser.lexer.c parser.tab.c parser.h
libparser_la_LIBADD = @ADD_LIBS@ @LEXLIB@
libparser_la_LDFLAGS = @ADD_LDFLAGS@ -L../
INCLUDES = @ADD_INCLS@ -I../ -I../../lib

EXTRA_DIST= parser.l parser.y
BUILT_SOURCES=parser.tab.h


%.tab.c %.tab.h: %.y
	@YACC@ -d -o$@ $<

%.lexer.c: %.l %.tab.c
	@LEX@ -o$@ $<
