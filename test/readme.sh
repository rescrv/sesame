#!/bin/sh
. $UTILS

expect << EOF
set timeout 1
spawn $SESAME insert -p $SESAME_PASSWORDFILE example.org alice
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
expect {
    "password: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "alice's password\n"
wait
EOF

expect << EOF
set timeout 1
spawn $SESAME show -p $SESAME_PASSWORDFILE example.org
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
expect {
    "alice's password" {}
    timeout { exit 1 }
    eof { exit 1 }
}

wait
EOF

expect << EOF
set timeout 1
spawn $SESAME insert -p $SESAME_PASSWORDFILE Amazon alice@example.org
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
expect {
    "password: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "a password for shopping\n"
wait
EOF

expect << EOF
set timeout 1
spawn $SESAME insert -p $SESAME_PASSWORDFILE Facebook alice199887XoXo
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
expect {
    "password: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "social-media\n"
wait
EOF

expect << EOF
set timeout 1
spawn $SESAME insert -p $SESAME_PASSWORDFILE Google alice@gmail.example.com
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
expect {
    "password: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "password-for-gmail\n"
wait
EOF

expect << EOF
set timeout 1
spawn $SESAME list -p $SESAME_PASSWORDFILE
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
expect {
    "example.org" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "Amazon" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "Facebook" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "Google" {}
    timeout { exit 1 }
    eof { exit 1 }
}

wait
EOF

expect << EOF
set timeout 1
spawn $SESAME list -p $SESAME_PASSWORDFILE e
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
expect {
    "example.org" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "Facebook" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "Google" {}
    timeout { exit 1 }
    eof { exit 1 }
}

wait
EOF

expect << EOF
set timeout 1
spawn $SESAME list -p $SESAME_PASSWORDFILE A
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
expect {
    "Amazon" {}
    timeout { exit 1 }
    eof { exit 1 }
}

wait
EOF

expect << EOF
set timeout 1
spawn $SESAME show -p $SESAME_PASSWORDFILE A
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
expect {
    "a password for shopping" {}
    timeout { exit 1 }
    eof { exit 1 }
}

wait
EOF

expect << EOF
set timeout 1
spawn $SESAME change-username -p $SESAME_PASSWORDFILE Amazon ALICE
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
wait
EOF

expect << EOF
set timeout 1
spawn $SESAME update-password -p $SESAME_PASSWORDFILE Amazon
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
expect {
    "password: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "a-new-password\n"
expect {
    "confirm password: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "a-new-password\n"
wait
EOF

expect << EOF
set timeout 1
spawn $SESAME show -p $SESAME_PASSWORDFILE Amazon
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
expect {
    "a-new-password" {}
    timeout { exit 1 }
    eof { exit 1 }
}

wait
EOF

expect << EOF
set timeout 1
spawn $SESAME rm -p $SESAME_PASSWORDFILE Amazon
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
expect {
    "" {}
    timeout { exit 1 }
    eof { exit 1 }
}

wait
EOF

expect << EOF
set timeout 1
spawn $SESAME cp -p $SESAME_PASSWORDFILE Facebook Facebook2
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
expect {
    "" {}
    timeout { exit 1 }
    eof { exit 1 }
}

wait
EOF

expect << EOF
set timeout 1
spawn $SESAME mv -p $SESAME_PASSWORDFILE Facebook Facebook3
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
wait
EOF

expect << EOF
set timeout 1
spawn $SESAME dump -p $SESAME_PASSWORDFILE
expect {
    "passphrase: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "our-passphrase\n"
expect {
    "key alg: Xs" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "kdf alg: BK" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "kdf rounds: 128" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "salt: 9b08392f8c973920082ae96bb12ae402" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "checksum: 7ae291f521d8f2cd" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "secret: 65aed04a4b1eebde69e895889f2babf03794b4788508e293e8c6a657cff562b9" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "login: example.org" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "username: alice" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "password: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "alice's password\n"
expect {
    "" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "login: Facebook3" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "username: alice199887XoXo" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "password: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "social-media\n"
expect {
    "" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "login: Google" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "username: alice@gmail.example.com" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "password: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "password-for-gmail\n"
expect {
    "" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "login: Facebook2" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "username: alice199887XoXo" {}
    timeout { exit 1 }
    eof { exit 1 }
}

expect {
    "password: " {}
    timeout { exit 1 }
    eof { exit 1 }
}
send "social-media\n"
wait
EOF
