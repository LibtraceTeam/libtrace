if LIBPACKETDUMP
TRACEDUMP_DIR=tracedump
endif

if LIBTRACE_TOOLS
SUBDIRS=traceanon tracemerge tracertstats tracesplit $(TRACEDUMP_DIR)
else
SUBDIRS=
endif

all-hook:
	for dir in $(SUBDIRS); do make -C $$dir; done

install-hook:
	for dir in $(SUBDIRS); do make -C $$dir install; done

clean-hook:
	for dir in $(SUBDIRS); do make -C $$dir clean; done
