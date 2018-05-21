/* Copyright (c) 2018, Robert Escriva
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of this project nor the names of its contributors may
 *       be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

/* C */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* POSIX */
#include <arpa/inet.h>
#include <err.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <unistd.h>
#include <wordexp.h>

/* BSD */
#if HAVE_BSD_STDLIB_H
#include <bsd/stdlib.h>
#endif
#if HAVE_BSD_STRING_H
#include <bsd/string.h>
#endif
#if HAVE_READPASSPHRASE_H
#include <readpassphrase.h>
#elif HAVE_BSD_READPASSPHRASE_H
#include <bsd/readpassphrase.h>
#else
#error portability problem
#endif
#if HAVE_LIBUTIL_H
#include <libutil.h>
#elif HAVE_BSD_LIBUTIL_H
#include <bsd/libutil.h>
#else
#error portability problem
#endif

#include "sha2.h"
#include "tweetnacl.h"
#if ENABLE_YUBIKEY
#include "yubikey.h"
#endif

#define KEYALG "Xs"
#define KDFALG "BK"

#ifdef SESAME_TEST_MODE
#define ALLOW_STDIN 1
#endif

#ifndef ALLOW_STDIN
#define ALLOW_STDIN 0
#endif

#if crypto_secretbox_xsalsa20poly1305_KEYBYTES != 32
#error keybytes changed
#endif
#if crypto_secretbox_xsalsa20poly1305_NONCEBYTES != 24
#error noncebytes changed
#endif
#if crypto_secretbox_xsalsa20poly1305_ZEROBYTES != 32
#error zerobytes changed
#endif
#if crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES != 16
#error boxzerobytes changed
#endif
#define KEYBYTES crypto_secretbox_xsalsa20poly1305_KEYBYTES
#define NONCEBYTES crypto_secretbox_xsalsa20poly1305_NONCEBYTES
#define ZEROBYTES crypto_secretbox_xsalsa20poly1305_ZEROBYTES
#define BOXZEROBYTES crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES

#if ZEROBYTES > BOXZEROBYTES
#define PAD ZEROBYTES
#define DIFF (ZEROBYTES - BOXZEROBYTES)
#else
#error assumption violated
#endif

#if NONCEBYTES + PAD > 128
#error assumption violated
#endif

struct key
{
    uint8_t keyalg[2];
    uint8_t kdfalg[2];
    uint32_t kdfrounds;
    uint8_t salt[16];
    uint8_t checksum[8];
    uint8_t secret[KEYBYTES];
};

// A yubikey challenge is a constant within the file that is provided to the
// yubikey in HMAC SHA1 mode.  The output of the HMAC is run through the KDF
// (struct key) to turn it from 20 random bytes to 32 random-ish bytes that are
// xor'd against key.secret.
struct yubikey
{
    uint32_t serial;
    uint8_t slot;
    uint8_t challenge[27];
    struct key key;
};

struct login
{
    char login[32];
    char username[32];
    char password[64];
};

#define PASSPHRASE_LEN 1024

struct sensitive_workspace
{
    char passphrase[PASSPHRASE_LEN];
    char confirmed[PASSPHRASE_LEN];
    uint8_t digest[SHA512_DIGEST_LENGTH];
    uint8_t xorkey[KEYBYTES];
    struct key key;
    struct yubikey yubikey;
    SHA2_CTX ctx;
    struct login login;
    struct login to_show;
    uint8_t login_nonce[NONCEBYTES];
    uint8_t login_message[256 - NONCEBYTES];
    uint8_t login_ciphertext[256 - NONCEBYTES];
    uint8_t buf[256];
    int fd; /* not really sensitive, but singleton is convenient */
};

extern char *__progname;

static void
usage(const char *error)
{
    if (error)
        fprintf(stderr, "%s\n", error);
    fprintf(stderr, "usage:"
        "\t%1$s init [-p passwordfile]\n"
        "\t%1$s show [-p passwordfile] pattern\n"
        "\t%1$s list [-p passwordfile] [pattern]\n"
        "\t%1$s insert [-p passwordfile] login username\n"
        "\t%1$s change-username [-p passwordfile] login username\n"
        "\t%1$s update-password [-p passwordfile] login\n"
        "\t%1$s mv [-p passwordfile] old-login new-login\n"
        "\t%1$s cp [-p passwordfile] old-login new-login\n"
        "\t%1$s rm [-p passwordfile] login\n"
        "\t%1$s add-yubikey [-p passwordfile] serial slot\n"
        "XXX generating passwords\n"
        , __progname);
    exit(1);
}

static struct sensitive_workspace*
initialize_sensitive_workspace()
{
    void* mapped = NULL;
    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize < 1)
        errx(1, "bad page size");
    size_t bytes = 0;
    while (!bytes && bytes < sizeof(struct sensitive_workspace)) {
        bytes += pagesize;
    }
    if ((mapped = mmap(NULL, bytes, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0)) == MAP_FAILED) {
        err(1, "mmap");
    }
    if (mlock(mapped, bytes) < 0) {
        err(1, "mlock");
    }
    explicit_bzero(mapped, bytes);
    if (sizeof(struct key) != 64)
        errx(1, "assumptions violated");
    if (sizeof(struct yubikey) > 96)
        errx(1, "assumptions violated");
    if (sizeof(struct login) > 128)
        errx(1, "assumptions violated");
    return mapped;
}

static const char*
default_passwordfile()
{
    const char* out = NULL;
    wordexp_t exp_result;
    if (wordexp("~/.passwords", &exp_result, 0) != 0)
        err(1, "wordexp");
    out = strdup(exp_result.we_wordv[0]);
    if (!out)
        err(1, "strdup");
    return out;
}

/* kdf function borrowed from OpenBSD: */
/* $OpenBSD: signify.c,v 1.128 2017/07/11 23:27:13 tedu Exp $ */
/*
 * Copyright (c) 2013 Ted Unangst <tedu@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
extern int
bcrypt_pbkdf(const char *pass, size_t passlen, const uint8_t *salt, size_t saltlen,
    uint8_t *key, size_t keylen, unsigned int rounds);
static void
kdf(struct sensitive_workspace* sw,
    uint8_t *salt, size_t saltlen, int rounds, int allowstdin, int confirm,
    uint8_t *key, size_t keylen)
{
    char* pass = sw->passphrase;
    int rppflags = RPP_ECHO_OFF;

    if (rounds == 0) {
        memset(key, 0, keylen);
        return;
    }

    if (allowstdin && !isatty(STDIN_FILENO))
        rppflags |= RPP_STDIN;
    if (!readpassphrase("passphrase: ", pass, PASSPHRASE_LEN, rppflags))
        errx(1, "unable to read passphrase");
    if (strlen(pass) == 0)
        errx(1, "please provide a passphrase");
    if (confirm && !(rppflags & RPP_STDIN)) {
        char* pass2 = sw->confirmed;
        if (!readpassphrase("confirm passphrase: ", pass2,
            PASSPHRASE_LEN, rppflags))
            errx(1, "unable to read passphrase");
        if (strcmp(pass, pass2) != 0)
            errx(1, "passwords don't match");
        explicit_bzero(pass2, PASSPHRASE_LEN);
    }
    if (bcrypt_pbkdf(pass, strlen(pass), salt, saltlen, key,
        keylen, rounds) == -1)
        errx(1, "bcrypt pbkdf");
    explicit_bzero(pass, PASSPHRASE_LEN);
}

static void
init(struct sensitive_workspace* sw,
     const char* passwordfile, int argc, const char* argv[])
{
    int i = 0;

    if (argc != 0)
        usage(NULL);

    arc4random_buf(sw->key.secret, sizeof(sw->key.secret));

    SHA512Init(&sw->ctx);
    SHA512Update(&sw->ctx, sw->key.secret, sizeof(sw->key.secret));
    SHA512Final(sw->digest, &sw->ctx);

    memmove(sw->key.keyalg, KEYALG, 2);
    memmove(sw->key.kdfalg, KDFALG, 2);
    sw->key.kdfrounds = 128;
    arc4random_buf(sw->key.salt, sizeof(sw->key.salt));
    memmove(sw->key.checksum, sw->digest, sizeof(sw->key.checksum));
    kdf(sw, sw->key.salt, sizeof(sw->key.salt),
        sw->key.kdfrounds, ALLOW_STDIN, 1,
        sw->xorkey, sizeof(sw->xorkey));
    for (i = 0; i < sizeof(sw->key.secret); i++)
        sw->key.secret[i] ^= sw->xorkey[i];

    sw->key.kdfrounds = htonl(sw->key.kdfrounds);
    sw->fd = open(passwordfile, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0600);
    if (sw->fd == -1)
        err(1, "can't create %s", passwordfile);
    if (flock(sw->fd, LOCK_EX) < 0)
        err(1, "can't lock %s", passwordfile);
    explicit_bzero(sw->buf, sizeof(sw->buf));
    memmove(sw->buf, &sw->key, sizeof(sw->key));
    if (write(sw->fd, sw->buf, sizeof(sw->buf)) != sizeof(sw->buf))
        err(1, "can't initialize %s", passwordfile);
    explicit_bzero(sw->buf, sizeof(sw->buf));
    /* three empty slots reserved for yubikeys */
    if (write(sw->fd, sw->buf, sizeof(sw->buf)) != sizeof(sw->buf))
        err(1, "can't initialize %s", passwordfile);
    if (write(sw->fd, sw->buf, sizeof(sw->buf)) != sizeof(sw->buf))
        err(1, "can't initialize %s", passwordfile);
    if (write(sw->fd, sw->buf, sizeof(sw->buf)) != sizeof(sw->buf))
        err(1, "can't initialize %s", passwordfile);
}

static int
unxor_secret(struct sensitive_workspace* sw)
{
    int i;
    for (i = 0; i < sizeof(sw->key.secret); i++)
        sw->key.secret[i] ^= sw->xorkey[i];
	SHA512Init(&sw->ctx);
	SHA512Update(&sw->ctx, sw->key.secret, sizeof(sw->key.secret));
	SHA512Final(sw->digest, &sw->ctx);
	if (memcmp(sw->key.checksum, sw->digest, sizeof(sw->key.checksum)) != 0)
		errx(1, "incorrect passphrase");
}

static int
try_reading_yubikey(struct sensitive_workspace* sw,
                    const char* passwordfile, int idx);

static void
read_passphrase_or_die(struct sensitive_workspace* sw,
                       const char* passwordfile)
{
    int i;
    if (lseek(sw->fd, 0, SEEK_SET) != 0)
        errx(1, "could not seek to start of passwordfile");
    if (read(sw->fd, sw->buf, sizeof(sw->buf)) != sizeof(sw->buf))
        err(1, "can't  read %s", passwordfile);
    memmove(&sw->key, sw->buf, sizeof(sw->key));
    sw->key.kdfrounds = ntohl(sw->key.kdfrounds);
    kdf(sw, sw->key.salt, sizeof(sw->key.salt),
        sw->key.kdfrounds, ALLOW_STDIN, 0,
        sw->xorkey, sizeof(sw->xorkey));
    unxor_secret(sw);
}

static void
open_and_initialize(struct sensitive_workspace* sw,
                    const char* passwordfile, int flags)
{
    sw->fd = open(passwordfile, flags|O_NOFOLLOW, 0600);
    if (sw->fd < 0)
        err(1, "can't open %s", passwordfile);
    if (flock(sw->fd, LOCK_EX) < 0)
        err(1, "can't lock %s", passwordfile);
#if ENABLE_YUBIKEY
    if (try_reading_yubikey(sw, passwordfile, 0) ||
        try_reading_yubikey(sw, passwordfile, 1) ||
        try_reading_yubikey(sw, passwordfile, 2)) {
    } else {
#endif
        explicit_bzero(&sw->yubikey, sizeof(sw->yubikey));
        read_passphrase_or_die(sw, passwordfile);
#if ENABLE_YUBIKEY
    }
#endif
    if (lseek(sw->fd, 1024, SEEK_SET) != 1024)
        errx(1, "could not seek to start of logins");
}

static int
read_next_login(struct sensitive_workspace* sw)
{
    char zerobuf[256];
    explicit_bzero(zerobuf, sizeof(zerobuf));
    while (1) {
        ssize_t amt = read(sw->fd, &sw->buf, sizeof(sw->buf));
        if (amt < 0)
            err(1, "read");
        if (amt == 0)
            return 0;
        if (amt != sizeof(sw->buf))
            errx(1, "short read");
        if (memcmp(sw->buf, zerobuf, sizeof(zerobuf)) == 0)
            continue;
        explicit_bzero(sw->login_nonce, sizeof(sw->login_nonce));
        explicit_bzero(sw->login_message, sizeof(sw->login_message));
        explicit_bzero(sw->login_ciphertext, sizeof(sw->login_ciphertext));
        memmove(sw->login_nonce, sw->buf, sizeof(sw->login_nonce));
        memmove(sw->login_ciphertext + BOXZEROBYTES, sw->buf + NONCEBYTES, 
                sizeof(sw->login_ciphertext) - BOXZEROBYTES);
        if (crypto_secretbox_xsalsa20poly1305_open(sw->login_message,
                                                   sw->login_ciphertext,
                                                   sizeof(sw->login_message),
                                                   sw->login_nonce,
                                                   sw->key.secret))
            errx(1, "decryption failed");
        memmove(&sw->login, sw->login_message + ZEROBYTES, sizeof(sw->login));
        return 1;
    }
}

static void
write_login(struct sensitive_workspace* sw)
{
    arc4random_buf(sw->login_nonce, sizeof(sw->login_nonce));
    explicit_bzero(sw->login_message, sizeof(sw->login_message));
    memmove(sw->login_message + PAD, &sw->login, sizeof(struct login));
    if (crypto_secretbox_xsalsa20poly1305(sw->login_ciphertext,
                                          sw->login_message,
                                          sizeof(sw->login_message),
                                          sw->login_nonce,
                                          sw->key.secret))
        errx(1, "encryption failed");

    memmove(sw->buf, sw->login_nonce, sizeof(sw->login_nonce));
    memmove(sw->buf + NONCEBYTES, sw->login_ciphertext + BOXZEROBYTES, 
            sizeof(sw->login_ciphertext) - BOXZEROBYTES);
    if (lseek(sw->fd, 0, SEEK_CUR) % 256 != 0)
        errx(1, "write not aligned; aborting");
    if (write(sw->fd, sw->buf, sizeof(sw->buf)) != sizeof(sw->buf))
        err(1, "write");
    fsync(sw->fd);
}

static void
step_back(struct sensitive_workspace* sw)
{
    off_t x = lseek(sw->fd, -256, SEEK_CUR);
    if (x < 0)
        err(1, "lseek");
    if (x < 1024)
        errx(1, "internal error");
}

static void
printf_hex(uint8_t* bytes, size_t sz)
{
    size_t i = 0;
    for (i = 0; i < sz; i++)
        printf("%02x", bytes[i]);
}

#define maxlen(X) strnlen((X), sizeof(X))

static void
dump(struct sensitive_workspace* sw,
     const char* passwordfile, int argc, const char* argv[])
{
    int i;

    if (argc != 0)
        usage("dump is internal");
    open_and_initialize(sw, passwordfile, O_RDONLY);

    if (sw->yubikey.serial != 0) {
        printf("from yubikey: %d slot %d\n", sw->yubikey.serial, sw->yubikey.slot);
    } else {
        printf("from passphrase\n");
    }
    printf("key alg: %.2s\n", sw->key.keyalg);
    printf("kdf alg: %.2s\n", sw->key.kdfalg);
    printf("kdf rounds: %u\n", sw->key.kdfrounds);
    printf("salt: ");
    printf_hex(sw->key.salt, sizeof(sw->key.salt));
    printf("\n");
    printf("checksum: ");
    printf_hex(sw->key.checksum, sizeof(sw->key.checksum));
    printf("\n");
    printf("secret: ");
    printf_hex(sw->key.secret, sizeof(sw->key.secret));
    printf("\n");

    while (read_next_login(sw)) {
        printf("\nlogin: %.*s\n", maxlen(sw->login.login), sw->login.login);
        printf("username: %.*s\n", maxlen(sw->login.username), sw->login.username);
        printf("password: %.*s\n", maxlen(sw->login.password), sw->login.password);
    }
}

extern int
regex_match(const char* regex, size_t regex_sz,
            const char* text, size_t text_sz);

static void
show(struct sensitive_workspace* sw,
     const char* passwordfile, int argc, const char* argv[])
{
    int found = 0;
    const char* pattern = "";

    if (argc != 1)
        usage(NULL);
    pattern = argv[0];
    open_and_initialize(sw, passwordfile, O_RDWR);

    while (read_next_login(sw)) {
        if (regex_match(pattern, strlen(pattern), 
                        sw->login.login, maxlen(sw->login.login))) {
            if (found)
                errx(1, "multiple logins match the provided pattern");
            memmove(&sw->to_show, &sw->login, sizeof(sw->to_show));
            found = 1;
        }
    }
    if (!found)
        errx(1, "could not find login matching %s", pattern);
    printf("%.*s\n", maxlen(sw->to_show.password), sw->to_show.password);
}

static void
list(struct sensitive_workspace* sw,
     const char* passwordfile, int argc, const char* argv[])
{
    const char* pattern = "";

    if (argc != 0 && argc != 1)
        usage(NULL);
    if (argc > 0)
        pattern = argv[0];
    open_and_initialize(sw, passwordfile, O_RDWR);

    while (read_next_login(sw)) {
        if (regex_match(pattern, strlen(pattern), 
                        sw->login.login, maxlen(sw->login.login)))
            printf("%.*s\n", maxlen(sw->login.login), sw->login.login);
    }
}

static void
insert(struct sensitive_workspace* sw,
       const char* passwordfile, int argc, const char* argv[])
{
    const char* login = NULL;
    const char* username = NULL;

    if (argc != 2)
        usage(NULL);
    login = argv[0];
    username = argv[1];
    open_and_initialize(sw, passwordfile, O_RDWR);

    while (read_next_login(sw)) {
        if (strncmp(login, sw->login.login, sizeof(sw->login.login)) == 0)
            errx(1, "login already in use");
    }

    explicit_bzero(&sw->login, sizeof(sw->login));
    if (strlcpy(sw->login.login, login, sizeof(sw->login.login)) >= sizeof(sw->login.login))
        errx(1, "login must be less than %d characters", sizeof(sw->login.login));
    if (strlcpy(sw->login.username, username, sizeof(sw->login.username)) >= sizeof(sw->login.username))
        errx(1, "username must be less than %d characters", sizeof(sw->login.username));
    if (!readpassphrase("password: ", sw->login.password, sizeof(sw->login.password), RPP_ECHO_OFF))
        errx(1, "unable to read passphrase");

    write_login(sw);
}

static void
change_username(struct sensitive_workspace* sw,
                const char* passwordfile, int argc, const char* argv[])
{
    const char* login = NULL;
    const char* username = NULL;

    if (argc != 2)
        usage(NULL);
    login = argv[0];
    username = argv[1];
    open_and_initialize(sw, passwordfile, O_RDWR);

    while (read_next_login(sw)) {
        if (strncmp(login, sw->login.login, sizeof(sw->login.login)) != 0)
            continue;
        if (strncmp(username, sw->login.username, sizeof(sw->login.username)) != 0) {
            if (strlcpy(sw->login.username, username, sizeof(sw->login.username)) >= sizeof(sw->login.username))
                errx(1, "username must be less than %d characters", sizeof(sw->login.username));

            step_back(sw);
            write_login(sw);
        }
        return;
    }
    errx(1, "could not find login %s", login);
}

static void
update_password(struct sensitive_workspace* sw,
                const char* passwordfile, int argc, const char* argv[])
{
    const char* login = NULL;

    if (argc != 1)
        usage(NULL);
    login = argv[0];
    open_and_initialize(sw, passwordfile, O_RDWR);

    while (read_next_login(sw)) {
        if (strncmp(login, sw->login.login, sizeof(sw->login.login)) != 0)
            continue;

        if (!readpassphrase("password: ", sw->passphrase, sizeof(sw->login.password), RPP_ECHO_OFF))
            errx(1, "unable to read password");
        if (strlen(sw->passphrase) == 0)
            errx(1, "please provide a password");
        if (!readpassphrase("confirm password: ", sw->confirmed, sizeof(sw->login.password), RPP_ECHO_OFF))
            errx(1, "unable to read password");
        if (strcmp(sw->passphrase, sw->confirmed) != 0)
            errx(1, "passwords don't match");
        if (strlcpy(sw->login.password, sw->passphrase, sizeof(sw->login.password)) >= sizeof(sw->login.password))
            errx(1, "buffer management error");

        step_back(sw);
        write_login(sw);
        return;
    }
    errx(1, "could not find login %s", login);
}

static void
mv(struct sensitive_workspace* sw,
   const char* passwordfile, int argc, const char* argv[])
{
    const char* old_login = NULL;
    const char* new_login = NULL;

    if (argc != 2)
        usage(NULL);
    old_login = argv[0];
    new_login = argv[1];
    open_and_initialize(sw, passwordfile, O_RDWR);

    while (read_next_login(sw)) {
        if (strncmp(old_login, sw->login.login, sizeof(sw->login.login)) != 0)
            continue;
        if (strlcpy(sw->login.login, new_login, sizeof(sw->login.login)) >= sizeof(sw->login.login))
            errx(1, "login must be less than %d characters", sizeof(sw->login.login));
        step_back(sw);
        write_login(sw);
        return;
    }
    errx(1, "could not find login %s", old_login);
}

static void
cp(struct sensitive_workspace* sw,
   const char* passwordfile, int argc, const char* argv[])
{
    const char* old_login = NULL;
    const char* new_login = NULL;

    if (argc != 2)
        usage(NULL);
    old_login = argv[0];
    new_login = argv[1];
    open_and_initialize(sw, passwordfile, O_RDWR);

    while (read_next_login(sw)) {
        if (strncmp(old_login, sw->login.login, sizeof(sw->login.login)) != 0)
            continue;
        if (strlcpy(sw->login.login, new_login, sizeof(sw->login.login)) >= sizeof(sw->login.login))
            errx(1, "login must be less than %d characters", sizeof(sw->login.login));
        if (lseek(sw->fd, 0, SEEK_END) < 0)
            err(1, "seek");
        write_login(sw);
        return;
    }
    errx(1, "could not find login %s", old_login);
}

static void
rm(struct sensitive_workspace* sw,
   const char* passwordfile, int argc, const char* argv[])
{
    const char* login = NULL;

    if (argc != 1)
        usage(NULL);
    login = argv[0];
    open_and_initialize(sw, passwordfile, O_RDWR);

    while (read_next_login(sw)) {
        if (strncmp(login, sw->login.login, sizeof(sw->login.login)) != 0)
            continue;
        step_back(sw);
        explicit_bzero(sw->buf, sizeof(sw->buf));
        if (write(sw->fd, sw->buf, sizeof(sw->buf)) != sizeof(sw->buf))
            err(1, "write");
        return;
    }
    errx(1, "could not find login %s", login);
}

#if ENABLE_YUBIKEY
static int
yubikey_fill_xorkey(struct sensitive_workspace* sw, int timeout_is_err)
{
    unsigned char* challenge = sw->buf;
    unsigned char* response = sw->buf + SESAME_CHALLENGE_SIZE;
    explicit_bzero(challenge, SESAME_CHALLENGE_SIZE);
    explicit_bzero(response, SESAME_RESPONSE_BUFFER_SIZE);
    memmove(challenge, sw->yubikey.challenge, SESAME_CHALLENGE_SIZE);
    int not_found = 0;
    int timed_out = 0;
    if (!sesame_yubikey_challenge_response(
                sw->yubikey.serial, sw->yubikey.slot,
                challenge, response,
                &not_found, &timed_out)) {
        if (not_found) {
            return 0;
        } else if (timed_out) {
            if (timeout_is_err)
                errx(1, "yubikey timed out");
            return 0;
        } else {
            errx(1, "couldn't chalresp yubikey");
        }
    }
    if (bcrypt_pbkdf(response, SESAME_RESPONSE_SIZE,
                sw->yubikey.key.salt, sizeof(sw->yubikey.key.salt),
                sw->xorkey, sizeof(sw->xorkey), sw->yubikey.key.kdfrounds) == -1)
        errx(1, "bcrypt pbkdf");
    return 1;
}

static int
try_reading_yubikey(struct sensitive_workspace* sw,
                    const char* passwordfile, int idx)
{
    assert(idx < 3);
    if (lseek(sw->fd, 256*(idx+1), SEEK_SET) != 256*(idx+1))
        errx(1, "could not seek to start of passwordfile");
    if (read(sw->fd, sw->buf, sizeof(sw->buf)) != sizeof(sw->buf))
        err(1, "can't  read %s", passwordfile);
    memmove(&sw->yubikey, sw->buf, sizeof(sw->yubikey));
    sw->yubikey.serial = ntohl(sw->yubikey.serial);
    sw->yubikey.key.kdfrounds = ntohl(sw->yubikey.key.kdfrounds);
    if (sw->yubikey.slot == 0)
        return 0;
    if (sw->yubikey.slot != 1 && sw->yubikey.slot != 2)
        errx(1, "invalid yubikey slot (%d)", sw->yubikey.slot);
    if (!yubikey_fill_xorkey(sw, 0))
        return 0;
    memmove(&sw->key, &sw->yubikey.key, sizeof(sw->key));
    unxor_secret(sw);
    return 1;
}

static void
add_yubikey(struct sensitive_workspace* sw,
            const char* passwordfile, int argc, const char* argv[])
{
    int i;
    unsigned long serial;
    unsigned long slot;
    char* end = NULL;
    unsigned char emptybuf[256];

    if (argc != 2)
        usage(NULL);
    open_and_initialize(sw, passwordfile, O_RDWR);

    serial = strtoul(argv[0], &end, 10);
    if (*end != '\0' || serial >= UINT32_MAX)
        errx(1, "invalid yubikey serial number");
    slot = strtoul(argv[1], &end, 10);
    if (*end != '\0' || (slot != 1 && slot != 2))
        errx(1, "invalid yubikey slot");
    sw->yubikey.serial = serial;
    sw->yubikey.slot = slot;
    arc4random_buf(sw->yubikey.challenge, sizeof(sw->yubikey.challenge));
    memmove(&sw->yubikey.key, &sw->key, sizeof(sw->yubikey.key));
    arc4random_buf(sw->yubikey.key.salt, sizeof(sw->yubikey.key.salt));
    if (!yubikey_fill_xorkey(sw, 1))
        errx(1, "yubikey not found");
    for (i = 0; i < sizeof(sw->yubikey.key.secret); i++)
        sw->yubikey.key.secret[i] ^= sw->xorkey[i];
    sw->yubikey.serial = htonl(sw->yubikey.serial);
    sw->yubikey.key.kdfrounds = htonl(sw->yubikey.key.kdfrounds);
    explicit_bzero(emptybuf, sizeof(emptybuf));
    for (i = 0; i < 3; i++) {
        if (lseek(sw->fd, 256*(i+1), SEEK_SET) != 256*(i+1))
            errx(1, "could not seek to read yubikey %d", i);
        if (read(sw->fd, sw->buf, sizeof(sw->buf)) != sizeof(sw->buf))
            err(1, "can't  read %s", passwordfile);
        if (memcmp(emptybuf, sw->buf, 256) == 0) {
            explicit_bzero(sw->buf, sizeof(sw->buf));
            memmove(sw->buf, &sw->yubikey, sizeof(sw->yubikey));
            if (lseek(sw->fd, 256*(i+1), SEEK_SET) != 256*(i+1))
                errx(1, "could not seek to write yubikey %d", i);
            if (write(sw->fd, sw->buf, sizeof(sw->buf)) != sizeof(sw->buf))
                err(1, "can't write yubikey");
            return;
        }
    }
    errx(1, "no empty slots for yubikey");
}

static void
rm_yubikey(struct sensitive_workspace* sw,
           const char* passwordfile, int argc, const char* argv[])
{
    int i;
    unsigned long serial;
    unsigned long slot;
    char* end = NULL;
    unsigned char emptybuf[256];

    if (argc != 2)
        usage(NULL);
    open_and_initialize(sw, passwordfile, O_RDWR);

    serial = htonl(strtoul(argv[0], &end, 10));
    if (*end != '\0' || serial >= UINT32_MAX)
        errx(1, "invalid yubikey serial number");
    slot = strtoul(argv[1], &end, 10);
    if (*end != '\0' || (slot != 1 && slot != 2))
        errx(1, "invalid yubikey slot");
    for (i = 0; i < 3; i++) {
        if (lseek(sw->fd, 256*(i+1), SEEK_SET) != 256*(i+1))
            errx(1, "could not seek to read yubikey %d", i);
        if (read(sw->fd, sw->buf, sizeof(sw->buf)) != sizeof(sw->buf))
            err(1, "can't  read %s", passwordfile);
        memmove(&sw->yubikey, sw->buf, sizeof(sw->yubikey));
        if (sw->yubikey.serial == serial) {
            if (lseek(sw->fd, 256*(i+1), SEEK_SET) != 256*(i+1))
                errx(1, "could not seek to clear yubikey %d", i);
            explicit_bzero(sw->buf, sizeof(sw->buf));
            if (write(sw->fd, sw->buf, sizeof(sw->buf)) != sizeof(sw->buf))
                err(1, "can't clear yubikey");
            return;
        }
    }
    errx(1, "yubikey not found");
}
#endif

int
main(int argc, const char* argv[])
{
    struct sensitive_workspace* sw = NULL;
    const char* passwordfile = NULL;
    const char* command = NULL;
    int ch;
#if ENABLE_YUBIKEY
    // initialize the yubikey workspace
    sesame_yubikey_init();
    // before the sensitive workspace (just in case the yubikey strays in its
    // pointer management---not that I actually think it has)
#endif
    sw = initialize_sensitive_workspace();
    if (argc <= 1)
        usage(NULL);
    command = argv[1];
    argc -= 1;
    argv += 1;
    while ((ch = getopt(argc, (char*const*)argv, "p:")) != -1) {
        switch (ch) {
        case 'p':
            passwordfile = optarg;
            break;
        default:
            usage(NULL);
        }
    }
    argc -= optind;
    argv += optind;
    if (!passwordfile)
        passwordfile = default_passwordfile();
    if (strcmp("init", command) == 0) {
        init(sw, passwordfile, argc, argv);
    } else if (strcmp("dump", command) == 0) {
        dump(sw, passwordfile, argc, argv);
    } else if (strcmp("show", command) == 0) {
        show(sw, passwordfile, argc, argv);
    } else if (strcmp("list", command) == 0) {
        list(sw, passwordfile, argc, argv);
    } else if (strcmp("insert", command) == 0) {
        insert(sw, passwordfile, argc, argv);
    } else if (strcmp("change-username", command) == 0) {
        change_username(sw, passwordfile, argc, argv);
    } else if (strcmp("update-password", command) == 0) {
        update_password(sw, passwordfile, argc, argv);
    } else if (strcmp("mv", command) == 0) {
        mv(sw, passwordfile, argc, argv);
    } else if (strcmp("cp", command) == 0) {
        cp(sw, passwordfile, argc, argv);
    } else if (strcmp("rm", command) == 0) {
        rm(sw, passwordfile, argc, argv);
    } else if (strcmp("add-yubikey", command) == 0) {
#if ENABLE_YUBIKEY
        add_yubikey(sw, passwordfile, argc, argv);
#else
        errx(1, "yubikey not supported");
#endif
    } else if (strcmp("rm-yubikey", command) == 0) {
#if ENABLE_YUBIKEY
        rm_yubikey(sw, passwordfile, argc, argv);
#else
        errx(1, "yubikey not supported");
#endif
    } else {
        usage(NULL);
    }
    return 0;
}
