/*!
 * secretbox.c - nacl secretbox for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://nacl.cr.yp.to/secretbox.html
 */

#include <stddef.h>
#include <torsion/poly1305.h>
#include <torsion/salsa20.h>
#include <torsion/secretbox.h>
#include <torsion/util.h>

/*
 * Constants
 */

static const unsigned char zero64[64] = {0};

/*
 * Secret Box
 */

void
secretbox_seal(unsigned char *sealed,
               const unsigned char *msg,
               size_t msg_len,
               const unsigned char *key,
               const unsigned char *nonce) {
  unsigned char *tag = sealed;
  unsigned char *ct = sealed + 16;
  unsigned char block[64];
  unsigned char *polykey = block;
  unsigned char *first = block + 32;
  poly1305_t poly;
  salsa20_t salsa;
  size_t i;

  salsa20_init(&salsa, key, 32, nonce, 24, 0);
  salsa20_encrypt(&salsa, block, zero64, 64);

  if (msg_len <= 32) {
    for (i = 0; i < msg_len; i++)
      ct[i] = msg[i] ^ first[i];
  } else {
    for (i = 0; i < 32; i++)
      ct[i] = msg[i] ^ first[i];

    salsa20_init(&salsa, key, 32, nonce, 24, 1);
    salsa20_encrypt(&salsa, ct + 32, msg + 32, msg_len - 32);
  }

  poly1305_init(&poly, polykey);
  poly1305_update(&poly, ct, msg_len);
  poly1305_final(&poly, tag);

  cleanse(block, sizeof(block));
  cleanse(&salsa, sizeof(salsa));
}

int
secretbox_open(unsigned char *msg,
               const unsigned char *sealed,
               size_t sealed_len,
               const unsigned char *key,
               const unsigned char *nonce) {
  const unsigned char *tag, *ct;
  unsigned char block[64];
  unsigned char *polykey = block;
  unsigned char *first = block + 32;
  unsigned char mac[16];
  poly1305_t poly;
  salsa20_t salsa;
  size_t ct_len;
  size_t i;
  int r;

  if (sealed_len < 16)
    return 0;

  tag = sealed;
  ct = sealed + 16;
  ct_len = sealed_len - 16;

  salsa20_init(&salsa, key, 32, nonce, 24, 0);
  salsa20_encrypt(&salsa, block, zero64, 64);

  poly1305_init(&poly, polykey);
  poly1305_update(&poly, ct, ct_len);
  poly1305_final(&poly, mac);

  r = poly1305_verify(mac, tag);

  if (ct_len <= 32) {
    for (i = 0; i < ct_len; i++)
      msg[i] = ct[i] ^ first[i];
  } else {
    for (i = 0; i < 32; i++)
      msg[i] = ct[i] ^ first[i];

    salsa20_init(&salsa, key, 32, nonce, 24, 1);
    salsa20_encrypt(&salsa, msg + 32, ct + 32, ct_len - 32);
  }

  cleanse(block, sizeof(block));
  cleanse(&salsa, sizeof(salsa));

  return r;
}

void
secretbox_derive(unsigned char *key, const unsigned char *secret) {
  salsa20_derive(key, secret, 32, zero64);
}
