#!/bin/sh
. $UTILS

OUTPUT=`echo our-passphrase | "$SESAME" dump -p "$SESAME_SRCDIR/test/v1.passwordfile" || exit`
SHA256SUM=`echo "$OUTPUT" | sha256sum | awk '{print $1}'`

VERIFY=`sha256sum << EOF | awk '{print $1}'
from passphrase
key alg: Xs
kdf alg: BK
kdf rounds: 128
salt: 9b08392f8c973920082ae96bb12ae402
checksum: 7ae291f521d8f2cd
secret: 65aed04a4b1eebde69e895889f2babf03794b4788508e293e8c6a657cff562b9

login: example.org
username: alice
password: alice's password

login: Facebook3
username: alice199887XoXo
password: social-media

login: Google
username: alice@gmail.example.com
password: password-for-gmail

login: Facebook2
username: alice199887XoXo
password: social-media
EOF`

if test "$SHA256SUM" != "$VERIFY"; then
    error format or debug output changed
fi
