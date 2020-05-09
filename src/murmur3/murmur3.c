/*!
 * murmur3.c - murmur3 for bcrypto
 * Copyright (c) 2016-2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/MurmurHash
 *   https://github.com/aappleby/smhasher
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "murmur3.h"

/*
 * Helpers
 */

#define ROTL32(x, y) ((x) << (y)) | ((x) >> (32 - (y)))

static uint32_t
read32le(const void *src) {
#ifndef WORDS_BIGENDIAN
  uint32_t w;
  memcpy(&w, src, sizeof(w));
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint32_t)p[0] << 0)
       | ((uint32_t)p[1] << 8)
       | ((uint32_t)p[2] << 16)
       | ((uint32_t)p[3] << 24);
#endif
}

/*
 * Murmur3
 */

uint32_t
murmur3_sum(const unsigned char *data, size_t len, uint32_t seed) {
  uint32_t h1 = seed;
  uint32_t c1 = UINT32_C(0xcc9e2d51);
  uint32_t c2 = UINT32_C(0x1b873593);
  uint32_t k1 = 0;
  size_t left = len;

  while (left >= 4) {
    k1 = read32le(data);

    k1 *= c1;
    k1 = ROTL32(k1, 15);
    k1 *= c2;

    h1 ^= k1;
    h1 = ROTL32(h1, 13);
    h1 = h1 * 5 + UINT32_C(0xe6546b64);

    data += 4;
    left -= 4;
  }

  k1 = 0;

  switch (left) {
    case 3:
      k1 ^= (uint32_t)(data[2] & 0xff) << 16;
    case 2:
      k1 ^= (uint32_t)(data[1] & 0xff) << 8;
    case 1:
      k1 ^= (uint32_t)(data[0] & 0xff) << 0;
      k1 *= c1;
      k1 = ROTL32(k1, 15);
      k1 *= c2;
      h1 ^= k1;
  }

  h1 ^= len;
  h1 ^= h1 >> 16;
  h1 *= UINT32_C(0x85ebca6b);
  h1 ^= h1 >> 13;
  h1 *= UINT32_C(0xc2b2ae35);
  h1 ^= h1 >> 16;

  return h1;
}

uint32_t
murmur3_tweak(const unsigned char *data,
              size_t len, uint32_t n, uint32_t tweak) {
  uint32_t seed = (n * UINT32_C(0xfba4c795)) + tweak;
  return murmur3_sum(data, len, seed);
}
