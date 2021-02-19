/*!
 * bf.h - extra blowfish functions for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef _TORSION_BF_H
#define _TORSION_BF_H

#include <stddef.h>
#include <stdint.h>
#include <torsion/cipher.h>

#define blowfish_stream2word __torsion_blowfish_stream2word
#define blowfish_expand0state __torsion_blowfish_expand0state
#define blowfish_expandstate __torsion_blowfish_expandstate
#define blowfish_enc __torsion_blowfish_enc
#define blowfish_dec __torsion_blowfish_dec

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
blowfish_enc(const blowfish_t *ctx, uint32_t *data, size_t len);

void
blowfish_dec(const blowfish_t *ctx, uint32_t *data, size_t len);

#endif /* _TORSION_BF_H */
