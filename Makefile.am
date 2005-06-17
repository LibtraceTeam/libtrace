SUBDIRS=lib
man_MANS = libtrace.h.3
EXTRA_DIST=examples docs $(man_MANS)

.PHONY: docs

bootstrap-clean:
	$(RM) -f Makefile.in aclocal.m4 compile config.* \
		configure depcomp install-sh ltmain.sh missing \
		mkinstalldirs stamp-h.in \
		lib/Makefile.in replace/libreplace.la  replace/Makefile.in
	$(RM) -rf autom4te.cache/
	
docs:
	doxygen libtrace.doxygen

