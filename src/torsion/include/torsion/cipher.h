/*!
 * cipher.h - ciphers for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef _TORSION_CIPHER_H
#define _TORSION_CIPHER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * Symbol Aliases
 */

#define blowfish_init torsion_blowfish_init
#define blowfish_stream2word torsion_blowfish_stream2word
#define blowfish_expand0state torsion_blowfish_expand0state
#define blowfish_expandstate torsion_blowfish_expandstate
#define blowfish_enc torsion_blowfish_enc
#define blowfish_dec torsion_blowfish_dec
#define blowfish_encrypt torsion_blowfish_encrypt
#define blowfish_decrypt torsion_blowfish_decrypt

/*
 * Structs
 */

typedef struct _blowfish_s {
  uint32_t S[4][256];
  uint32_t P[18];
} blowfish_t;

/*
 * Blowfish
 */

void
blowfish_init(blowfish_t *ctx,
              const unsigned char *key, size_t key_len,
              const unsigned char *salt, size_t salt_len);

uint32_t
blowfish_stream2word(const unsigned char *data, size_t len, size_t *off);

void
blowfish_expand0state(blowfish_t *ctx,
                      const unsigned char *key,
                      size_t key_len);

void
blowfish_expandstate(blowfish_t *ctx,
                     const unsigned char *key, size_t key_len,
                     const unsigned char *data, size_t data_len);

void
blowfish_enc(blowfish_t *ctx, uint32_t *data, size_t len);

void
blowfish_dec(blowfish_t *ctx, uint32_t *data, size_t len);

void
blowfish_encrypt(blowfish_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src);

void
blowfish_decrypt(blowfish_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_CIPHER_H */
