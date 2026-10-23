AM_CFLAGS = $(NGFW_CFLAGS) -I$(top_srcdir)/include -I$(top_builddir)/include

# ADR-003 (designs/02-architecture.md section 7): userland shared code lives in
# the single static library libngfw; subsystems are directory + header contracts.
noinst_LIBRARIES = libngfw.a

libngfw_a_SOURCES = \
	lib/platform/npx_mem.c \
	lib/platform/npx_time.c \
	lib/platform/npx_error.c \
	lib/platform/npx_mutex.c \
	lib/platform/npx_poll.c \
	lib/platform/npx_pipe.c \
	lib/platform/npx_fd.c \
	lib/core/nfc_log.c \
	lib/core/nfc_evloop.c \
	lib/core/nfc_config.c \
	lib/selftest/nst.c \
	lib/selftest/nst_platform.c \
	lib/selftest/nst_core.c

bin_PROGRAMS = ngfw
# The source directory name must not match the artifact name ("ngfw"): the
# automake link rule removes the program file in the build directory, which
# would collide with a same-named source directory.
ngfw_SOURCES = cli/ngfw.c
ngfw_LDADD = libngfw.a
