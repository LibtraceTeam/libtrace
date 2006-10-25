#SWIG=/usr/bin/swig
EXTRA_DIST = libtrace.i

#lib_LTLIBRARIES = libtrace.la
#libtrace_la_SOURCES = libtrace_wrap.c
#INCLUDES = -I/usr/local/python2.3

libtrace_wrap.c: libtrace.i
	$(SWIG) -python $(SWIG_ARGS) -o $@ $<

