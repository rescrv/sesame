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

/* C */
#include <assert.h>
#include <err.h>
#include <stdio.h>

/* ykpers */
#include <ykpers-1/ykcore.h>
#include <ykpers-1/ykdef.h>

/* sesame */
#include "yubikey.h"

static void
yubikey_fatal()
{
    const char* msg = yk_errno == YK_EUSBERR
                    ? yk_usb_strerror()
                    : yk_strerror(yk_errno);
    errx(1, "yubikey: %s", msg);
}

static YK_KEY*
find_yubikey(unsigned int find_key)
{
    int i = 0;
	YK_KEY *yk = 0;
    unsigned int serial = 0;
    for (i = 0; i < MAX_YUBIKEYS; i++) {
	    if (!(yk = yk_open_key(i))) {
            if (yk_errno == YK_ENOKEY)
                return NULL;
            yubikey_fatal();
        }
        if (!yk_get_serial(yk, 0, 0, &serial))
            yubikey_fatal();
        if (serial == find_key)
            return yk;
        if (!yk_close_key(yk))
            yubikey_fatal();
    }
}

void
sesame_yubikey_init()
{
    if (!yk_init())
        yubikey_fatal();
}

int
sesame_yubikey_challenge_response(unsigned int key_serial, int slot,
                                  const unsigned char* challenge,
                                  unsigned char* response,
                                  int* not_found,
                                  int* timed_out)
{
    *not_found = 0;
    *timed_out = 0;
    assert(slot == 1 || slot == 2);
    static const int slots[] = {0, SLOT_CHAL_HMAC1, SLOT_CHAL_HMAC2};
    YK_KEY* yk = find_yubikey(key_serial);
    if (!yk) {
        *not_found = 1;
        return 0;
    }
    fprintf(stderr, "touch your yubikey...\n");
    if (!yk_challenge_response(yk, slots[slot], 1,
                64, challenge, 64, response)) {
        if (yk_errno == YK_ETIMEOUT) {
            *timed_out = 1;
            return 0;
        }
        yubikey_fatal();
    }
    return 1;
}
