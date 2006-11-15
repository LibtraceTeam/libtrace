BUILT_SOURCES=python_wrap.c
SWIG_SOURCES=libtrace.i

#SWIG=/usr/bin/swig
python_PYTHON=libtrace.py
pyexec_LTLIBRARIES=_libtrace.la
_libtrace_la_SOURCES=python_wrap.c
_libtrace_la_LDFLAGS=-module
_libtrace_la_LIBADD=../lib/libtrace.la
_libtrace_la_CFLAGS=-I../lib -I/usr/include/python@PYTHON_VERSION@/

python_wrap.c: $(SWIG_SOURCES)
	$(SWIG) -Wall $(SWIG_PYTHON_OPT) -I../lib -o $@ $<


