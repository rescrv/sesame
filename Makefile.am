if MAKE_NO_PRINT_DIRECTORY
AM_MAKEFLAGS = --no-print-directory
endif
AM_CFLAGS    = -fvisibility=hidden $(WANAL_CFLAGS)
TESTS_ENVIRONMENT = . $(abs_top_srcdir)/test/env.sh "${abs_top_srcdir}" "${abs_top_builddir}" "${VERSION}";

EXTRA_DIST =
EXTRA_DIST += LICENSE
EXTRA_DIST += README
EXTRA_DIST += test/env.sh
EXTRA_DIST += test/util.sh
EXTRA_DIST += test/passwordfile
EXTRA_DIST += test/v1.passwordfile
EXTRA_DIST += portability.patch
EXTRA_DIST += readme-to-tests
EXTRA_DIST += update.sh

bin_PROGRAMS = sesame

noinst_HEADERS =
noinst_HEADERS += blf.h
noinst_HEADERS += sha2.h
noinst_HEADERS += tweetnacl.h
noinst_HEADERS += yubikey.h

sesame_SOURCES =
sesame_SOURCES += bcrypt_pbkdf.c
sesame_SOURCES += blowfish.c
sesame_SOURCES += explicit_bzero.c
sesame_SOURCES += regex_match.c
sesame_SOURCES += sesame.c
sesame_SOURCES += sha2.c
sesame_SOURCES += tweetnacl.c
if ENABLE_YUBIKEY
sesame_SOURCES += yubikey.c
endif
sesame_LDADD = $(BSDLIB)
if ENABLE_YUBIKEY
sesame_LDADD += -lykpers-1
endif

# Build the same binary, but with SESAME_TEST_MODE defined
check_PROGRAMS = test/sesame
test_sesame_SOURCES = $(sesame_SOURCES)
test_sesame_CFLAGS = -DSESAME_TEST_MODE
test_sesame_LDADD = $(sesame_LDADD)

dist_check_SCRIPTS =
dist_check_SCRIPTS += test/base.sh
dist_check_SCRIPTS += test/format.sh
dist_check_SCRIPTS += test/passphrases.sh
dist_check_SCRIPTS += test/readme.sh

TESTS =
TESTS += test/base.sh
TESTS += test/format.sh
TESTS += test/passphrases.sh
TESTS += test/readme.sh
