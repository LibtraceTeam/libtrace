SUBDIRS=lib docs libpacketdump

AUTOMAKE_OPTIONS = 1.5

if HAS_DOXYGEN
man_MANS = docs/doxygen/man/man3/trace*.3 docs/doxygen/man/man3/libtrace*.3 
endif
#man_MANS = @MANPAGES@
EXTRA_DIST=examples tools
#docs/html docs/latex docs/man $(man_MANS)

.PHONY: docs

bootstrap-clean:
	$(RM) -f Makefile.in aclocal.m4 compile config.* \
		configure depcomp install-sh ltmain.sh missing \
		mkinstalldirs stamp-h.in \
		lib/Makefile.in replace/libreplace.la  replace/Makefile.in
	$(RM) -rf autom4te.cache/

dist-hook:
	for dir in $(EXTRA_DIST); do \
		rm -rf `find $(distdir)/$$dir -name CVS` ; \
		for i in `\ls $(distdir)/$$dir `; do make -C $(distdir)/$$dir/$$i clean; done \
	done

if HAS_DOXYGEN
docs/doxygen/man/man3/*.3: docs
else
docs/doxygen/man/man3/*.3: 
endif

#docs:
#	doxygen libtrace.doxygen

install-man-hook: docs
