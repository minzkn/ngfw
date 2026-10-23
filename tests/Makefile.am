AM_CFLAGS = $(NGFW_CFLAGS) -I$(top_srcdir)/include -I$(top_builddir)/include

# Unit tests are thin runners over the same suites that `ngfw selftest`
# executes at runtime, so there is exactly one definition per check (R07).
check_PROGRAMS = test_platform test_core

test_platform_SOURCES = test_platform.c
test_platform_LDADD = $(top_builddir)/src/libngfw.a

test_core_SOURCES = test_core.c
test_core_LDADD = $(top_builddir)/src/libngfw.a

TESTS = $(check_PROGRAMS)
