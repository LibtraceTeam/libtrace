SUBDIRS=lib
man_MANS = docs/man/man3/trace*.3 docs/man/man3/libtrace*.3 docs/man/man3/get*.3 
#man_MANS = @MANPAGES@
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
	rm -rf `find $(distdir)/examples -name CVS`

docs/man/man3/*.3:
	doxygen libtrace.doxygen

docs:
	doxygen libtrace.doxygen

install-man-hook: docs
