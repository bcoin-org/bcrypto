/**
 * Parts of this software are based on chacha20-simple:
 * http://chacha20.insanecoding.org/
 *
 *   Copyright (C) 2014 insane coder
 *
 *   Permission to use, copy, modify, and distribute this software for any
 *   purpose with or without fee is hereby granted, provided that the above
 *   copyright notice and this permission notice appear in all copies.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 *   SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 *   IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   This implementation is intended to be simple, many optimizations can be
 *   performed.
 */

#include <assert.h>
#include <string.h>
#include <stdint.h>

#include "salsa20.h"

#define ROTL32(v, n) ((v) << (n)) | ((v) >> (32 - (n)))

#define READLE(p)               \
  (((uint32_t)((p)[0]))         \
  | ((uint32_t)((p)[1]) << 8)   \
  | ((uint32_t)((p)[2]) << 16)  \
  | ((uint32_t)((p)[3]) << 24))

#define WRITELE(b, i)        \
  (b)[0] = i & 0xFF;         \
  (b)[1] = (i >> 8) & 0xFF;  \
  (b)[2] = (i >> 16) & 0xFF; \
  (b)[3] = (i >> 24) & 0xFF;

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define QUARTERROUND(x, a, b, c, d) \
  x[b] ^= ROTL32(x[a] + x[d], 7);   \
  x[c] ^= ROTL32(x[b] + x[a], 9);   \
  x[d] ^= ROTL32(x[c] + x[b], 13);  \
  x[a] ^= ROTL32(x[d] + x[c], 18)

void
bcrypto_salsa20_init(bcrypto_salsa20_ctx *ctx,
                     const uint8_t *key,
                     size_t key_len,
                     const uint8_t *nonce,
                     size_t nonce_len,
                     uint64_t counter) {
  assert(key_len == 16 || key_len == 32);

  uint8_t key_[32];
  uint8_t nonce_[16];

  memcpy(&key_[0], key, MIN(32, key_len));
  memcpy(&nonce_[0], nonce, MIN(16, nonce_len));

  // XSalsa20
  if (nonce_len == 24) {
    bcrypto_salsa20_derive(&key_[0], key, key_len, nonce, 16);
    memcpy(&nonce_[0], &nonce[16], 8);
    key_len = 32;
    nonce_len = 8;
  }

  const char *constants = (key_len == 32)
    ? "expand 32-byte k"
    : "expand 16-byte k";

  ctx->state[0] = READLE(constants + 0);
  ctx->state[1] = READLE(key_ + 0);
  ctx->state[2] = READLE(key_ + 4);
  ctx->state[3] = READLE(key_ + 8);
  ctx->state[4] = READLE(key_ + 12);
  ctx->state[5] = READLE(constants + 4);

  if (nonce_len == 8) {
    ctx->state[6] = READLE(nonce_ + 0);
    ctx->state[7] = READLE(nonce_ + 4);
    ctx->state[8] = counter & 0xffffffffu;
    ctx->state[9] = counter >> 32;
  } else if (nonce_len == 12) {
    ctx->state[6] = READLE(nonce_ + 0);
    ctx->state[7] = READLE(nonce_ + 4);
    ctx->state[8] = READLE(nonce_ + 8);
    ctx->state[9] = counter & 0xffffffffu;
  } else if (nonce_len == 16) {
    ctx->state[6] = READLE(nonce_ + 0);
    ctx->state[7] = READLE(nonce_ + 4);
    ctx->state[8] = READLE(nonce_ + 8);
    ctx->state[9] = READLE(nonce_ + 12);
  } else {
    assert(0 && "invalid nonce size for salsa20");
  }

  ctx->state[10] = READLE(constants + 8);
  ctx->state[11] = READLE(key_ + 16 % key_len);
  ctx->state[12] = READLE(key_ + 20 % key_len);
  ctx->state[13] = READLE(key_ + 24 % key_len);
  ctx->state[14] = READLE(key_ + 28 % key_len);
  ctx->state[15] = READLE(constants + 12);

  ctx->available = 0;
}

void
bcrypto_salsa20_block(bcrypto_salsa20_ctx *ctx, uint32_t output[16]) {
  uint32_t *ctr = ctx->state + 8;
  int i = 10;

  memcpy(output, ctx->state, sizeof(ctx->state));

  while (i--) {
    QUARTERROUND(output, 0, 4, 8, 12);
    QUARTERROUND(output, 5, 9, 13, 1);
    QUARTERROUND(output, 10, 14, 2, 6);
    QUARTERROUND(output, 15, 3, 7, 11);
    QUARTERROUND(output, 0, 1, 2, 3);
    QUARTERROUND(output, 5, 6, 7, 4);
    QUARTERROUND(output, 10, 11, 8, 9);
    QUARTERROUND(output, 15, 12, 13, 14);
  }

  for (i = 0; i < 16; i++) {
    uint32_t result = output[i] + ctx->state[i];
    WRITELE((uint8_t *)(output + i), result);
  }

  if (++ctr[0] == 0)
    ctr[1] += 1;
}

static inline
void bcrypto_salsa20_xor(uint8_t *stream,
                         uint8_t **out,
                         const uint8_t **in,
                         size_t length) {
  uint8_t *end_stream = stream + length;
  do {
    *(*out)++ = *(*in)++ ^ *stream++;
  } while (stream < end_stream);
}

void
bcrypto_salsa20_encrypt(bcrypto_salsa20_ctx *ctx,
                        uint8_t *out,
                        const uint8_t *in,
                        size_t length) {
  if (length) {
    uint8_t *k = (uint8_t *)ctx->stream;

    if (ctx->available) {
      size_t amount = MIN(length, ctx->available);
      size_t size = sizeof(ctx->stream) - ctx->available;
      bcrypto_salsa20_xor(k + size, &out, &in, amount);
      ctx->available -= amount;
      length -= amount;
    }

    while (length) {
      size_t amount = MIN(length, sizeof(ctx->stream));
      bcrypto_salsa20_block(ctx, ctx->stream);
      bcrypto_salsa20_xor(k, &out, &in, amount);
      length -= amount;
      ctx->available = sizeof(ctx->stream) - amount;
    }
  }
}

void
bcrypto_salsa20_derive(uint8_t *out,
                       const uint8_t *key,
                       size_t key_len,
                       const uint8_t *nonce,
                       size_t nonce_len) {
  assert(key_len == 16 || key_len == 32);
  assert(nonce_len == 16);

  const char *constants = (key_len == 32)
    ? "expand 32-byte k"
    : "expand 16-byte k";

  uint32_t state[16];

  state[0] = READLE(constants + 0);
  state[1] = READLE(key + 0);
  state[2] = READLE(key + 4);
  state[3] = READLE(key + 8);
  state[4] = READLE(key + 12);
  state[5] = READLE(constants + 4);
  state[6] = READLE(nonce + 0);
  state[7] = READLE(nonce + 4);
  state[8] = READLE(nonce + 8);
  state[9] = READLE(nonce + 12);
  state[10] = READLE(constants + 8);
  state[11] = READLE(key + 16 % key_len);
  state[12] = READLE(key + 20 % key_len);
  state[13] = READLE(key + 24 % key_len);
  state[14] = READLE(key + 28 % key_len);
  state[15] = READLE(constants + 12);

  int i = 10;

  while (i--) {
    QUARTERROUND(state, 0, 4, 8, 12);
    QUARTERROUND(state, 5, 9, 13, 1);
    QUARTERROUND(state, 10, 14, 2, 6);
    QUARTERROUND(state, 15, 3, 7, 11);
    QUARTERROUND(state, 0, 1, 2, 3);
    QUARTERROUND(state, 5, 6, 7, 4);
    QUARTERROUND(state, 10, 11, 8, 9);
    QUARTERROUND(state, 15, 12, 13, 14);
  }

  WRITELE(out + 0, state[0]);
  WRITELE(out + 4, state[5]);
  WRITELE(out + 8, state[10]);
  WRITELE(out + 12, state[15]);
  WRITELE(out + 16, state[6]);
  WRITELE(out + 20, state[7]);
  WRITELE(out + 24, state[8]);
  WRITELE(out + 28, state[9]);
}
