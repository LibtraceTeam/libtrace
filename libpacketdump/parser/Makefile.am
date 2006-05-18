lib_LTLIBRARIES = libparser.la
#include_HEADERS = parser.h

#libparser_la_SOURCES = libconfig.c libconfig.h config_internal.h config.lexer.c config.parser.h configuration.h config.parser.c
libparser_la_SOURCES = parser.lexer.c parser.tab.c parser.h
libparser_la_LIBADD = @ADD_LIBS@ -lfl
libparser_la_LDFLAGS = @ADD_LDFLAGS@ -lfl

EXTRA_DIST= parser.l parser.y


%.tab.c: %.y
	bison -d -o$@ $<

%.lexer.c: %.l
	flex -o$@ $<
