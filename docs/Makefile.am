DOXYGEN_CONF = libtrace.doxygen
DOXYGEN_FOLDERS = doxygen/html doxygen/man

if HAS_DOXYGEN
EXTRA_DIST = $(DOXYGEN_FOLDERS)
else
EXTRA_DIST = 
endif

doxygen/html: doxy

doxygen/latex: doxy

doxygen/man: doxy


documentation: latex

latex: *.tex
	latex2html -dir html -split 0 *.tex

all: doxy

distclean: doxyclean

doxy:
	@if test x"$(libtrace_doxygen)" = xtrue ; then \
	  if test -f $(DOXYGEN_CONF) ; then \
	    doxygen $(DOXYGEN_CONF) ; \
	  else \
	    echo "Sorry, doxygen conf file $(DOXYGEN_CONF) does not exist" ; \
	  fi ; \
	else \
	  echo "Sorry, you do not have doxygen in your PATH." ; \
	fi

doxyclean:
	@for folder in $(DOXYGEN_FOLDERS) ; do \
	  if test -d $$folder ; then \
	    rm -rf $$folder ; \
	  fi \
	done

