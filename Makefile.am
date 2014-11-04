LIBPACKETDUMP_DIR = libpacketdump
TOOLS_DIR = tools
WANDIO_DIR=libwandio
SUBDIRS = $(WANDIO_DIR) lib $(LIBPACKETDUMP_DIR) $(TOOLS_DIR) docs examples

ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = 1.9 foreign

if HAS_DOXYGEN
man_MANS = docs/doxygen/man/man3/trace*.3 docs/doxygen/man/man3/libtrace*.3 
endif
EXTRA_DIST=libtrace.sln libtrace.vcproj test-convert.vcproj \
		   test-format.vcproj test-pcap-bpf.vcproj

.PHONY: docs

bootstrap-clean:
	$(RM) -f Makefile.in aclocal.m4 compile config.* \
		configure depcomp install-sh ltmain.sh missing \
		mkinstalldirs stamp-h.in \
		lib/Makefile.in replace/libreplace.la  replace/Makefile.in
	$(RM) -rf autom4te.cache/

if HAS_DOXYGEN
docs/doxygen/man/man3/*.3: docs
else
docs/doxygen/man/man3/*.3: 
endif

install-man-hook: docs
