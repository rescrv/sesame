set -ex

# These utilities are tested largely by test/passphrases.sh, which uses the two
# driver functions to test with conditionals and then cross-checks that against
# the assert/mustfail calls.  The rest is just trusting inspection of running
# the command.  If you change these, walk through the output of that test to
# confirm it looks the same.

error() {
    echo $@
    exit 1
}

assert() {
    if $@; then
        true
    else
        error command failed
    fi
}

mustfail() {
    if $@; then
        error command unexpectedly succeeded
    else
        true
    fi
}

sesame_setup() {
    export SESAME_PASSWORDFILE=`mktemp ${SESAME_BUILDDIR}/sesame-test.XXXXXX`
    cp "$SESAME_SRCDIR/test/passwordfile" "${SESAME_PASSWORDFILE}"
    trap 'rm "$SESAME_PASSWORDFILE"' exit
}

sesame_ll_driver() {
    PASS=$1
    shift
    CMD=$1
    shift
    echo "$PASS" | "$SESAME" "$CMD" -p "$SESAME_PASSWORDFILE" $@
}

sesame_driver() {
    sesame_ll_driver our-passphrase $@
}

sesame_setup
