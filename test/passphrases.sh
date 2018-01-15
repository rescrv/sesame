#!/bin/sh
. $UTILS

if sesame_ll_driver not-our-passphrase dump; then
    error sesame accepted incorrect passphrase
fi
if sesame_ll_driver our-passphrase dump;then
    # test the assert utils here
    mustfail sesame_ll_driver not-our-passphrase dump
    assert sesame_ll_driver our-passphrase dump
    assert sesame_driver dump
    exit 0
fi
error sesame rejected the correct passphrase
