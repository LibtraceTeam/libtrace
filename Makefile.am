SUBDIRS=lib
man_MANS = docs/man/man3/[a-zA-Z]*.3
EXTRA_DIST=examples docs/html docs/latex docs/man $(man_MANS)

.PHONY: docs

bootstrap-clean:
	$(RM) -f Makefile.in aclocal.m4 compile config.* \
		configure depcomp install-sh ltmain.sh missing \
		mkinstalldirs stamp-h.in \
		lib/Makefile.in replace/libreplace.la  replace/Makefile.in
	$(RM) -rf autom4te.cache/

dist-hook:
	for i in `\ls examples | grep -v CVS`; do make -C examples/$$i clean; done

docs:
	doxygen libtrace.doxygen

install-man-hook: docs
