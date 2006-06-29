BUILT_SOURCES = libtrace_wrap.c
SWIG_SOURCES = libtrace.i

pkgpython_PYTHON = libtrace.py
pkgpyexec_LTLIBRARIES = _libtrace.la
_libtrace_la_SOURCES = libtrace_wrap.c $(SWIG_SOURCES)
_libtrace_la_CPPFLAGS = $(SWIG_PYTHON_CPPFLAGS) -I$(top_srcdir)/lib -I/usr/local/include -shared
#_libtrace_la_CXXFLAGS = $(SWIG_PYTHON_CPPFLAGS) -I$(top_srcdir)/lib -g -shared -I/usr/local/include
_libtrace_la_LDFLAGS = -module  -L/usr/local/lib -version-info @LIBTRACE_MAJOR@:@LIBTRACE_MINOR@:@LIBTRACE_MID@
_libtrace_la_LIBADD = -ltrace

libtrace_wrap.c : $(SWIG_SOURCES)
	$(SWIG) $(SWIG_PYTHON_OPT) -I$(top_srcdir)/lib -o $@ $<

clean-hook:
	rm libtrace.py libtrace_wrap.c
