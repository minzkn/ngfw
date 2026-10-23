ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src tests

# VERSION is the single source of truth for product identity; bootstrap
# regenerates the autotools plumbing on a fresh checkout. Public headers are
# listed here so that `make dist` carries the full interface contract.
EXTRA_DIST = \
	VERSION \
	bootstrap \
	include/ngfw/platform.h \
	include/ngfw/log.h \
	include/ngfw/evloop.h \
	include/ngfw/config.h \
	include/ngfw/selftest.h \
	include/ngfw/version.h.in \
	scripts/docker-matrix.sh

.PHONY: selftest
selftest: all
	$(top_builddir)/src/ngfw selftest all
