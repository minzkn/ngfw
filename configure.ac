# ngfw - Next Generation Firewall.
# The authoritative design lives in designs/; the build contract is
# designs/16-build-deploy.md and the version source of truth is VERSION.

AC_PREREQ([2.71])
AC_INIT([ngfw],
        [m4_esyscmd([sh -c "sed -n 's/^version=//p' VERSION 2>/dev/null | tr -d ' \r\n'"])],
        [https://github.com/minzkn/ngfw/issues])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([VERSION])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.16 foreign subdir-objects -Wall])

AC_USE_SYSTEM_EXTENSIONS

AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_AR
AC_PROG_RANLIB

# Product identity read from the VERSION file (designs/20-naming-versioning.md).
NGFW_PRODUCT="`sed -n 's/^product=//p' "$srcdir/VERSION" 2>/dev/null | tr -d ' \r\n'`"
AS_IF([test -z "$NGFW_PRODUCT"],
      [AC_MSG_ERROR([failed to read the product= entry from VERSION])])
AC_SUBST([NGFW_PRODUCT])

# Strict C11 with warnings-as-errors by default (R02; see
# docs/standards/c11-coding-notes.md for the exact rule set).
AC_ARG_ENABLE([werror],
  [AS_HELP_STRING([--disable-werror],
                  [do not turn compiler warnings into errors])],
  [], [enable_werror=yes])
NGFW_CFLAGS="-std=c11 -pedantic-errors -Wall -Wextra"
AS_IF([test "x$enable_werror" = "xyes"], [NGFW_CFLAGS="$NGFW_CFLAGS -Werror"])
AC_SUBST([NGFW_CFLAGS])

AC_CHECK_HEADERS([sys/epoll.h])
AC_CHECK_FUNCS([clock_gettime strerror_r epoll_create1 pipe2])
AC_FUNC_STRERROR_R
AC_SEARCH_LIBS([pthread_create], [pthread])

AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile include/ngfw/version.h])
AC_OUTPUT
