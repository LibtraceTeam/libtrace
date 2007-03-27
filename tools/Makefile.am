# tracedump depends on libpacketdump
TRACEDUMP_DIR=tracepktdump

SUBDIRS=traceanon tracemerge tracesplit $(TRACEDUMP_DIR) tracertstats tracestats
SUBDIRS+=tracereport traceflow

all-hook:
	for dir in $(SUBDIRS); do make -C $$dir; done

install-hook:
	for dir in $(SUBDIRS); do make -C $$dir install; done

clean-hook:
	for dir in $(SUBDIRS); do make -C $$dir clean; done
