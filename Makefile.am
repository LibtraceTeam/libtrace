SUBDIRS=lib
EXTRA_DIST=examples docs

CLEANFILES = *.html *.gif *.css

noinst_DATA = index.html

index_html_SOURCES = @PACKAGE@.doxygen

index.html: @PACKAGE@.doxygen
	doxygen @PACKAGE@.doxygen
