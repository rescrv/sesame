#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([sesame], [0.0.dev], [robert@rescrv.net])
m4_define([serial_tests], [
    m4_esyscmd([case `automake --version | head -n 1` in
                *1.11*);;
                *) echo serial-tests;;
                esac])
])
AM_INIT_AUTOMAKE(foreign serial_tests subdir-objects dist-bzip2)
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_SRCDIR([sesame.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
STRICT_WARNINGS
AS_IF([make -h 2>/dev/null | grep no-print-directory > /dev/null], [make_no_print=yes])
AM_CONDITIONAL([MAKE_NO_PRINT_DIRECTORY], [test x"${make_no_print}" != x])
AC_CHECK_FUNC([strlcpy],[BSDLIB=],[BSDLIB=-lbsd])
AC_SUBST([BSDLIB], [$BSDLIB])
AC_CHECK_HEADER([bsd/stdlib.h],[AC_DEFINE([HAVE_BSD_STDLIB_H],[1],[Define to 1 if you have the <bsd/stdlib.h> header file.])],,)
AC_CHECK_HEADER([bsd/string.h],[AC_DEFINE([HAVE_BSD_STRING_H],[1],[Define to 1 if you have the <bsd/string.h> header file.])],,)
AC_CHECK_HEADER([readpassphrase.h],[AC_DEFINE([HAVE_READPASSPHRASE_H],[1],[Define to 1 if you have the <readpassphrase.h> header file.])],,)
AC_CHECK_HEADER([bsd/readpassphrase.h],[AC_DEFINE([HAVE_BSD_READPASSPHRASE_H],[1],[Define to 1 if you have the <bsd/readpassphrase.h> header file.])],,)
AC_CHECK_HEADER([libutil.h],[AC_DEFINE([HAVE_LIBUTIL_H],[1],[Define to 1 if you have the <libutil.h> header file.])],,)
AC_CHECK_HEADER([bsd/libutil.h],[AC_DEFINE([HAVE_BSD_LIBUTIL_H],[1],[Define to 1 if you have the <bsd/libutil.h> header file.])],,)
AC_ARG_ENABLE([yubikey], [AS_HELP_STRING([--enable-yubikey],
              [enable yubikey challenge-response support @<:@default: yes@:>@])],
              [enable_yubikey=${enable_yubikey}], [enable_yubikey=yes])
if test x"${enable_yubikey}" = xyes; then
    AC_DEFINE([ENABLE_YUBIKEY],[1],[Define to 1 if compiled with yubikey support.])
fi
AM_CONDITIONAL([ENABLE_YUBIKEY], [test x"${enable_yubikey}" = xyes])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
