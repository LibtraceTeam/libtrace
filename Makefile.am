LIBPACKETDUMP_DIR = libpacketdump
TOOLS_DIR = tools
if LIBTRACE_SWIG
SWIG_DIR = swig
endif
SUBDIRS = lib $(LIBPACKETDUMP_DIR) $(TOOLS_DIR) $(SWIG_DIR) docs examples

ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = 1.5

if HAS_DOXYGEN
man_MANS = docs/doxygen/man/man3/trace*.3 docs/doxygen/man/man3/libtrace*.3 
endif
EXTRA_DIST=examples libtrace.sln libtrace.vcproj test-convert.vcproj \
		   test-format.vcproj test-pcap-bpf.vcproj

.PHONY: docs

bootstrap-clean:
	$(RM) -f Makefile.in aclocal.m4 compile config.* \
		configure depcomp install-sh ltmain.sh missing \
		mkinstalldirs stamp-h.in \
		lib/Makefile.in replace/libreplace.la  replace/Makefile.in
	$(RM) -rf autom4te.cache/

dist-hook:
	for dir in $(EXTRA_DIST); do \
		if [ ! -d $(distdir)/$$dir ]; then continue; fi; \
		rm -rf `find $(distdir)/$$dir -name CVS` ; \
		rm -rf `find $(distdir)/$$dir -name .svn` ; \
		for i in `\ls -d $(distdir)/$$dir `; do make -C $(distdir)/$$dir/$$i clean; done \
	done
	rm -rf $(distdir)/tools/tracereport/.{svn,deps}

if HAS_DOXYGEN
docs/doxygen/man/man3/*.3: docs
else
docs/doxygen/man/man3/*.3: 
endif

install-man-hook: docs
