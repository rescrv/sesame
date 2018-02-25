#!/bin/sh
. $UTILS

OUTPUT=`echo our-passphrase | "$SESAME" dump -p "$SESAME_SRCDIR/test/v1.passwordfile" || exit`
SHA256SUM=`echo "$OUTPUT" | sha256sum | awk '{print $1}'`

if test "$SHA256SUM" != d5d1f6d9091193facbfcacfcf825d912f98168df6cc104c5d879a0705f8e5e0a; then
    error format inadvertently changed
fi
