/*!
 * encoding.c - string encodings for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on bitcoin/bitcoin:
 *   Copyright (c) 2009-2019, The Bitcoin Core Developers (MIT License).
 *   Copyright (c) 2009-2019, The Bitcoin Developers (MIT License).
 *   https://github.com/bitcoin/bitcoin
 *
 * Parts of this software are based on Bitcoin-ABC/bitcoin-abc:
 *   Copyright (c) 2009-2019, The Bitcoin Developers (MIT License).
 *   Copyright (c) 2009-2017, The Bitcoin Core Developers (MIT License).
 *   https://github.com/Bitcoin-ABC/bitcoin-abc
 *
 * Parts of this software are based on sipa/bech32:
 *   Copyright (c) 2017, Pieter Wuille (MIT License).
 *   https://github.com/sipa/bech32
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <torsion/encoding.h>
#include "internal.h"

/*
 * Base16 Engine
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc4648
 */

static const char *base16_charset = "0123456789abcdef";

static const int8_t base16_table[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
   0,  1,  2,  3,  4,  5,  6,  7,
   8,  9, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1
};

static size_t
base16_encode_size0(size_t len) {
  return len * 2;
}

static void
base16_encode0(char *dst, size_t *dstlen,
               const uint8_t *src, size_t srclen,
               int endian) {
  size_t i = endian < 0 ? srclen - 1 : 0;
  size_t j = 0;

  while (srclen--) {
    dst[j++] = base16_charset[src[i] >> 4];
    dst[j++] = base16_charset[src[i] & 15];

    i += endian;
  }

  dst[j] = '\0';

  if (dstlen)
    *dstlen = j;
}

static size_t
base16_decode_size0(size_t len) {
  return len / 2;
}

static int
base16_decode0(uint8_t *dst, size_t *dstlen,
               const char *src, size_t srclen,
               int endian) {
  size_t i = endian < 0 ? srclen - 2 : 0;
  size_t j = 0;
  uint8_t z = 0;

  if (srclen & 1)
    return 0;

  srclen /= 2;
  endian *= 2;

  while (srclen--) {
    uint8_t hi = base16_table[(uint8_t)src[i + 0]];
    uint8_t lo = base16_table[(uint8_t)src[i + 1]];

    z |= hi | lo;

    dst[j++] = (hi << 4) | lo;

    i += endian;
  }

  /* Check for errors at the end. */
  if (z & 0x80)
    return 0;

  if (dstlen)
    *dstlen = j;

  return 1;
}

static int
base16_test0(const char *str, size_t len) {
  if (len & 1)
    return 0;

  while (len--) {
    if (base16_table[(uint8_t)str[len]] == -1)
      return 0;
  }

  return 1;
}

/*
 * Base16
 */

size_t
base16_encode_size(size_t len) {
  return base16_encode_size0(len);
}

void
base16_encode(char *dst, size_t *dstlen,
              const uint8_t *src, size_t srclen) {
  base16_encode0(dst, dstlen, src, srclen, 1);
}

size_t
base16_decode_size(size_t len) {
  return base16_decode_size0(len);
}

int
base16_decode(uint8_t *dst, size_t *dstlen,
              const char *src, size_t srclen) {
  return base16_decode0(dst, dstlen, src, srclen, 1);
}

int
base16_test(const char *str, size_t len) {
  return base16_test0(str, len);
}

/*
 * Base16 (Little Endian)
 */

size_t
base16le_encode_size(size_t len) {
  return base16_encode_size0(len);
}

void
base16le_encode(char *dst, size_t *dstlen,
                const uint8_t *src, size_t srclen) {
  base16_encode0(dst, dstlen, src, srclen, -1);
}

size_t
base16le_decode_size(size_t len) {
  return base16_decode_size0(len);
}

int
base16le_decode(uint8_t *dst, size_t *dstlen,
                const char *src, size_t srclen) {
  return base16_decode0(dst, dstlen, src, srclen, -1);
}

int
base16le_test(const char *str, size_t len) {
  return base16_test0(str, len);
}

/*
 * Base32 Engine
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc4648
 *   https://github.com/bitcoin/bitcoin/blob/11d486d/src/utilstrencodings.cpp#L230
 */

static const char *base32_charset = "abcdefghijklmnopqrstuvwxyz234567";
static const char *base32hex_charset = "0123456789abcdefghijklmnopqrstuv";

static const int8_t base32_table[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, 26, 27, 28, 29, 30, 31,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,
   7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22,
  23, 24, 25, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,
   7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22,
  23, 24, 25, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1
};

static const int8_t base32hex_table[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
   0,  1,  2,  3,  4,  5,  6,  7,
   8,  9, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24,
  25, 26, 27, 28, 29, 30, 31, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24,
  25, 26, 27, 28, 29, 30, 31, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1
};

static const size_t base32_padding[5] = {0, 6, 4, 3, 1};

static size_t
base32_encode_size0(size_t len, int pad) {
  size_t size = (len / 5) * 8;
  size_t mode = len % 5;

  switch (mode) {
    case 4:
      size += 2;
    case 3:
      size += 1;
    case 2:
      size += 2;
    case 1:
      size += 1;
  }

  if (mode > 0) {
    size += 1;

    if (pad)
      size += base32_padding[mode];
  }

  return size;
}

static void
base32_encode0(char *dst, size_t *dstlen,
               const uint8_t *src, size_t srclen,
               const char *charset, int pad) {
  size_t mode = 0;
  uint8_t left = 0;
  size_t j = 0;
  size_t i;

  for (i = 0; i < srclen; i++) {
    uint8_t ch = src[i];

    switch (mode) {
      case 0:
        dst[j++] = charset[ch >> 3];
        left = (ch & 7) << 2;
        mode = 1;
        break;
      case 1:
        dst[j++] = charset[left | (ch >> 6)];
        dst[j++] = charset[(ch >> 1) & 31];
        left = (ch & 1) << 4;
        mode = 2;
        break;
      case 2:
        dst[j++] = charset[left | (ch >> 4)];
        left = (ch & 15) << 1;
        mode = 3;
        break;
      case 3:
        dst[j++] = charset[left | (ch >> 7)];
        dst[j++] = charset[(ch >> 2) & 31];
        left = (ch & 3) << 3;
        mode = 4;
        break;
      case 4:
        dst[j++] = charset[left | (ch >> 5)];
        dst[j++] = charset[ch & 31];
        mode = 0;
        break;
    }
  }

  if (mode > 0) {
    dst[j++] = charset[left];

    if (pad) {
      for (i = 0; i < base32_padding[mode]; i++)
        dst[j++] = '=';
    }
  }

  dst[j] = '\0';

  if (dstlen)
    *dstlen = j;
}

static size_t
base32_decode_size0(const char *str, size_t len) {
  size_t i, size, mode;

  for (i = 0; i < 6 && len > 0; i++) {
    if (str[len - 1] == '=')
      len -= 1;
  }

  size = (len / 8) * 5;
  mode = len % 8;

  switch (mode) {
    case 7:
      size += 1;
    case 6: /* Invalid. */
    case 5:
      size += 1;
    case 4:
      size += 1;
    case 3: /* Invalid. */
    case 2:
      size += 1;
  }

  return size;
}

static int
base32_decode0(uint8_t *dst, size_t *dstlen,
               const char *src, size_t srclen,
               const int8_t *table, int unpad) {
  size_t mode = 0;
  uint8_t left = 0;
  size_t j = 0;
  size_t i;

  for (i = 0; i < srclen; i++) {
    uint8_t val = table[(uint8_t)src[i]];

    if (val & 0x80)
      break;

    switch (mode) {
      case 0:
        left = val;
        mode = 1;
        break;
      case 1:
        dst[j++] = (left << 3) | (val >> 2);
        left = val & 3;
        mode = 2;
        break;
      case 2:
        left = (left << 5) | val;
        mode = 3;
        break;
      case 3:
        dst[j++] = (left << 1) | (val >> 4);
        left = val & 15;
        mode = 4;
        break;
      case 4:
        dst[j++] = (left << 4) | (val >> 1);
        left = val & 1;
        mode = 5;
        break;
      case 5:
        left = (left << 5) | val;
        mode = 6;
        break;
      case 6:
        dst[j++] = (left << 2) | (val >> 3);
        left = val & 7;
        mode = 7;
        break;
      case 7:
        dst[j++] = (left << 5) | val;
        left = 0;
        mode = 0;
        break;
    }
  }

  if (mode == 1 || mode == 3 || mode == 6)
    return 0;

  if (left > 0)
    return 0;

  if (srclen != i + (-mode & 7) * unpad)
    return 0;

  for (; i < srclen; i++) {
    if (src[i] != '=')
      return 0;
  }

  if (dstlen)
    *dstlen = j;

  return 1;
}

static int
base32_test0(const char *src, size_t srclen,
             const int8_t *table, int unpad) {
  size_t i, mode;

  for (i = 0; i < srclen; i++) {
    if (table[(uint8_t)src[i]] == -1)
      break;
  }

  mode = i % 8;

  switch (mode) {
    case 1:
      return 0;
    case 2:
      if (table[(uint8_t)src[i - 1]] & 3)
        return 0;
      break;
    case 3:
      return 0;
    case 4:
      if (table[(uint8_t)src[i - 1]] & 15)
        return 0;
      break;
    case 5:
      if (table[(uint8_t)src[i - 1]] & 1)
        return 0;
      break;
    case 6:
      return 0;
    case 7:
      if (table[(uint8_t)src[i - 1]] & 7)
        return 0;
      break;
  }

  if (srclen != i + (-mode & 7) * unpad)
    return 0;

  for (; i < srclen; i++) {
    if (src[i] != '=')
      return 0;
  }

  return 1;
}

/*
 * Base32
 */

size_t
base32_encode_size(size_t len, int pad) {
  return base32_encode_size0(len, pad);
}

void
base32_encode(char *dst, size_t *dstlen,
              const uint8_t *src, size_t srclen, int pad) {
  base32_encode0(dst, dstlen, src, srclen, base32_charset, pad);
}

size_t
base32_decode_size(const char *str, size_t len) {
  return base32_decode_size0(str, len);
}

int
base32_decode(uint8_t *dst, size_t *dstlen,
              const char *src, size_t srclen, int unpad) {
  return base32_decode0(dst, dstlen, src, srclen, base32_table, unpad);
}

int
base32_test(const char *src, size_t srclen, int unpad) {
  return base32_test0(src, srclen, base32_table, unpad);
}

/*
 * Base32-Hex
 */

size_t
base32hex_encode_size(size_t len, int pad) {
  return base32_encode_size0(len, pad);
}

void
base32hex_encode(char *dst, size_t *dstlen,
                 const uint8_t *src, size_t srclen, int pad) {
  base32_encode0(dst, dstlen, src, srclen, base32hex_charset, pad);
}

size_t
base32hex_decode_size(const char *str, size_t len) {
  return base32_decode_size0(str, len);
}

int
base32hex_decode(uint8_t *dst, size_t *dstlen,
                 const char *src, size_t srclen, int unpad) {
  return base32_decode0(dst, dstlen, src, srclen, base32hex_table, unpad);
}

int
base32hex_test(const char *src, size_t srclen, int unpad) {
  return base32_test0(src, srclen, base32hex_table, unpad);
}

/*
 * Base58
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
 */

static const char *base58_charset =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int8_t base58_table[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,
   7,  8, -1, -1, -1, -1, -1, -1,
  -1,  9, 10, 11, 12, 13, 14, 15,
  16, -1, 17, 18, 19, 20, 21, -1,
  22, 23, 24, 25, 26, 27, 28, 29,
  30, 31, 32, -1, -1, -1, -1, -1,
  -1, 33, 34, 35, 36, 37, 38, 39,
  40, 41, 42, 43, -1, 44, 45, 46,
  47, 48, 49, 50, 51, 52, 53, 54,
  55, 56, 57, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1
};

int
base58_encode(char *dst, size_t *dstlen,
              const uint8_t *src, size_t srclen) {
  size_t zeroes = 0;
  size_t length = 0;
  size_t i, j, k, size;
  unsigned long carry;
  uint8_t *b58;

  if (srclen > 0x7fffffff)
    return 0;

  for (i = 0; i < srclen; i++) {
    if (src[i] != 0)
      break;

    zeroes += 1;
  }

  size = (uint64_t)(srclen - zeroes) * 138 / 100 + 1;
  b58 = malloc(size);

  if (b58 == NULL)
    return 0;

  memset(b58, 0, size);

  for (; i < srclen; i++) {
    carry = src[i];

    for (j = 0, k = size - 1; j < size; j++, k--) {
      if (carry == 0 && j >= length)
        break;

      carry += (unsigned long)b58[k] << 8;
      b58[k] = carry % 58;
      carry /= 58;
    }

    ASSERT(carry == 0);

    length = j;
  }

  i = size - length;

  while (i < size && b58[i] == 0)
    i += 1;

  for (j = 0; j < zeroes; j++)
    dst[j] = '1';

  while (i < size)
    dst[j++] = base58_charset[b58[i++]];

  dst[j] = '\0';

  if (dstlen)
    *dstlen = j;

  free(b58);

  return 1;
}

int
base58_decode(uint8_t *dst, size_t *dstlen,
              const char *src, size_t srclen) {
  size_t zeroes = 0;
  size_t length = 0;
  size_t i, j, k, size;
  unsigned long carry;
  uint8_t *b256;
  uint8_t val;

  if (srclen > 0xffffffff)
    return 0;

  for (i = 0; i < srclen; i++) {
    if (src[i] != '1')
      break;

    zeroes += 1;
  }

  size = (uint64_t)srclen * 733 / 1000 + 1;
  b256 = malloc(size);

  if (b256 == NULL)
    return 0;

  memset(b256, 0, size);

  for (; i < srclen; i++) {
    val = base58_table[(uint8_t)src[i]];

    if (val & 0x80) {
      free(b256);
      return 0;
    }

    carry = val;

    for (j = 0, k = size - 1; j < size; j++, k--) {
      if (carry == 0 && j >= length)
        break;

      carry += (unsigned long)b256[k] * 58;
      b256[k] = carry;
      carry >>= 8;
    }

    ASSERT(carry == 0);

    length = j;
  }

  i = 0;

  while (i < size && b256[i] == 0)
    i += 1;

  for (j = 0; j < zeroes; j++)
    dst[j] = 0;

  while (i < size)
    dst[j++] = b256[i++];

  if (dstlen)
    *dstlen = j;

  free(b256);

  return 1;
}

int
base58_test(const char *str, size_t len) {
  while (len--) {
    if (base58_table[(uint8_t)str[len]] == -1)
      return 0;
  }

  return 1;
}

/*
 * Base64 Engine
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc4648
 */

static const char *base64_charset =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char *base64url_charset =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static const int8_t base64_table[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, 62, -1, -1, -1, 63,
  52, 53, 54, 55, 56, 57, 58, 59,
  60, 61, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,
   7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22,
  23, 24, 25, -1, -1, -1, -1, -1,
  -1, 26, 27, 28, 29, 30, 31, 32,
  33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48,
  49, 50, 51, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1
};

static const int8_t base64url_table[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, 62, -1, -1,
  52, 53, 54, 55, 56, 57, 58, 59,
  60, 61, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,
   7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22,
  23, 24, 25, -1, -1, -1, -1, 63,
  -1, 26, 27, 28, 29, 30, 31, 32,
  33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48,
  49, 50, 51, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1
};

static size_t
base64_encode_size0(size_t len, int pad) {
  size_t size = (len / 3) * 4;

  switch (len % 3) {
    case 1:
      size += 2;
      if (pad)
        size += 2;
      break;
    case 2:
      size += 3;
      if (pad)
        size += 1;
      break;
  }

  return size;
}

static void
base64_encode0(char *dst, size_t *dstlen,
               const uint8_t *src, size_t srclen,
               const char *charset, int pad) {
  size_t left = srclen;
  size_t i = 0;
  size_t j = 0;

  while (left >= 3) {
    uint8_t c1 = src[i++];
    uint8_t c2 = src[i++];
    uint8_t c3 = src[i++];

    dst[j++] = charset[c1 >> 2];
    dst[j++] = charset[((c1 & 3) << 4) | (c2 >> 4)];
    dst[j++] = charset[((c2 & 0x0f) << 2) | (c3 >> 6)];
    dst[j++] = charset[c3 & 0x3f];

    left -= 3;
  }

  switch (left) {
    case 1: {
      uint8_t c1 = src[i++];

      dst[j++] = charset[c1 >> 2];
      dst[j++] = charset[(c1 & 3) << 4];

      if (pad) {
        dst[j++] = '=';
        dst[j++] = '=';
      }

      break;
    }

    case 2: {
      uint8_t c1 = src[i++];
      uint8_t c2 = src[i++];

      dst[j++] = charset[c1 >> 2];
      dst[j++] = charset[((c1 & 3) << 4) | (c2 >> 4)];
      dst[j++] = charset[(c2 & 0x0f) << 2];

      if (pad)
        dst[j++] = '=';

      break;
    }
  }

  dst[j] = '\0';

  if (dstlen)
    *dstlen = j;
}

static size_t
base64_decode_size0(const char *str, size_t len) {
  size_t size, rem;

  if (len > 0 && str[len - 1] == '=')
    len -= 1;

  if (len > 0 && str[len - 1] == '=')
    len -= 1;

  size = (len / 4) * 3;
  rem = len & 3;

  if (rem)
    size += rem - 1;

  return size;
}

static int
base64_decode0(uint8_t *dst, size_t *dstlen,
               const char *src, size_t srclen,
               const int8_t *table) {
  size_t left = srclen;
  size_t i = 0;
  size_t j = 0;

  if (left > 0 && src[left - 1] == '=')
    left -= 1;

  if (left > 0 && src[left - 1] == '=')
    left -= 1;

  if ((left & 3) == 1) /* Fail early. */
    return 0;

  while (left >= 4) {
    uint8_t t1 = table[(uint8_t)src[i++]];
    uint8_t t2 = table[(uint8_t)src[i++]];
    uint8_t t3 = table[(uint8_t)src[i++]];
    uint8_t t4 = table[(uint8_t)src[i++]];

    if ((t1 | t2 | t3 | t4) & 0x80)
      return 0;

    dst[j++] = (t1 << 2) | (t2 >> 4);
    dst[j++] = (t2 << 4) | (t3 >> 2);
    dst[j++] = (t3 << 6) | (t4 >> 0);

    left -= 4;
  }

  switch (left) {
    case 1: {
      return 0;
    }

    case 2: {
      uint8_t t1 = table[(uint8_t)src[i++]];
      uint8_t t2 = table[(uint8_t)src[i++]];

      if ((t1 | t2) & 0x80)
        return 0;

      dst[j++] = (t1 << 2) | (t2 >> 4);

      if (t2 & 15)
        return 0;

      break;
    }

    case 3: {
      uint8_t t1 = table[(uint8_t)src[i++]];
      uint8_t t2 = table[(uint8_t)src[i++]];
      uint8_t t3 = table[(uint8_t)src[i++]];

      if ((t1 | t2 | t3) & 0x80)
        return 0;

      dst[j++] = (t1 << 2) | (t2 >> 4);
      dst[j++] = (t2 << 4) | (t3 >> 2);

      if (t3 & 3)
        return 0;

      break;
    }
  }

  if (dstlen)
    *dstlen = j;

  return 1;
}

static int
base64_test0(const char *str, size_t len, const int8_t *table) {
  size_t i;

  if (len > 0 && str[len - 1] == '=')
    len -= 1;

  if (len > 0 && str[len - 1] == '=')
    len -= 1;

  if ((len & 3) == 1) /* Fail early. */
    return 0;

  for (i = 0; i < len; i++) {
    if (table[(uint8_t)str[i]] == -1)
      return 0;
  }

  switch (len & 3) {
    case 1:
      return 0;
    case 2:
      return (table[(uint8_t)str[len - 1]] & 15) == 0;
    case 3:
      return (table[(uint8_t)str[len - 1]] & 3) == 0;
  }

  return 1;
}

static int
base64_check_padding(const char *str, size_t len, size_t size) {
  switch (size % 3) {
    case 0: {
      if (len == 0)
        return 1;

      if (len == 1)
        return str[0] != '=';

      return str[len - 2] != '='
          && str[len - 1] != '=';
    }

    case 1: {
      return len >= 4
          && str[len - 2] == '='
          && str[len - 1] == '=';
    }

    case 2: {
      return len >= 4
          && str[len - 2] != '='
          && str[len - 1] == '=';
    }

    default: {
      return 0; /* Unreachable. */
    }
  }
}

/*
 * Base64
 */

size_t
base64_encode_size(size_t len) {
  return base64_encode_size0(len, 1);
}

void
base64_encode(char *dst, size_t *dstlen,
              const uint8_t *src, size_t srclen) {
  base64_encode0(dst, dstlen, src, srclen, base64_charset, 1);
}

size_t
base64_decode_size(const char *str, size_t len) {
  return base64_decode_size0(str, len);
}

int
base64_decode(uint8_t *dst, size_t *dstlen,
              const char *src, size_t srclen) {
  size_t size = base64_decode_size0(src, srclen);

  if (!base64_check_padding(src, srclen, size))
    return 0;

  return base64_decode0(dst, dstlen, src, srclen, base64_table);
}

int
base64_test(const char *str, size_t len) {
  size_t size = base64_decode_size0(str, len);

  if (!base64_check_padding(str, len, size))
    return 0;

  return base64_test0(str, len, base64_table);
}

/*
 * Base64-URL
 */

size_t
base64url_encode_size(size_t len) {
  return base64_encode_size0(len, 0);
}

void
base64url_encode(char *dst, size_t *dstlen,
                 const uint8_t *src, size_t srclen) {
  base64_encode0(dst, dstlen, src, srclen, base64url_charset, 0);
}

size_t
base64url_decode_size(const char *str, size_t len) {
  return base64_decode_size0(str, len);
}

int
base64url_decode(uint8_t *dst, size_t *dstlen,
                 const char *src, size_t srclen) {
  if (!base64_check_padding(src, srclen, 0))
    return 0;

  return base64_decode0(dst, dstlen, src, srclen, base64url_table);
}

int
base64url_test(const char *str, size_t len) {
  if (!base64_check_padding(str, len, 0))
    return 0;

  return base64_test0(str, len, base64url_table);
}

/*
 * Bech32
 *
 * Resources:
 *   https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
 *   https://github.com/sipa/bech32/blob/master/ref/c/segwit_addr.c
 *   https://github.com/bitcoin/bitcoin/blob/master/src/bech32.cpp
 */

static const char *bech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t bech32_table[128] = {
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30,
   7,  5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8,
  23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,
   6,  4,  2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8,
  23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,
   6,  4,  2, -1, -1, -1, -1, -1
};

static uint32_t
bech32_polymod(uint32_t pre) {
  uint32_t b = pre >> 25;

  return ((pre & UINT32_C(0x1ffffff)) << 5)
    ^ (UINT32_C(0x3b6a57b2) & -((b >> 0) & 1))
    ^ (UINT32_C(0x26508e6d) & -((b >> 1) & 1))
    ^ (UINT32_C(0x1ea119fa) & -((b >> 2) & 1))
    ^ (UINT32_C(0x3d4233dd) & -((b >> 3) & 1))
    ^ (UINT32_C(0x2a1462b3) & -((b >> 4) & 1));
}

int
bech32_serialize(char *dst,
                 size_t *dstlen,
                 const char *hrp,
                 size_t hrplen,
                 const uint8_t *src,
                 size_t srclen) {
  uint32_t chk = 1;
  size_t j = 0;
  size_t i;

  if (hrplen + 1 + srclen + 6 > BECH32_MAX_SERIALIZE_SIZE)
    return 0;

  for (i = 0; i < hrplen; i++) {
    uint8_t ch = hrp[i];

    if (ch < 33 || ch > 126)
      return 0;

    if (ch >= 65 && ch <= 90)
      return 0;

    chk = bech32_polymod(chk) ^ (ch >> 5);
  }

  chk = bech32_polymod(chk);

  for (i = 0; i < hrplen; i++) {
    uint8_t ch = hrp[i];

    chk = bech32_polymod(chk) ^ (ch & 0x1f);

    dst[j++] = ch;
  }

  dst[j++] = '1';

  for (i = 0; i < srclen; i++) {
    uint8_t ch = src[i];

    if (ch >> 5)
      return 0;

    chk = bech32_polymod(chk) ^ ch;

    dst[j++] = bech32_charset[ch];
  }

  for (i = 0; i < 6; i++)
    chk = bech32_polymod(chk);

  chk ^= 1;

  for (i = 0; i < 6; i++)
    dst[j++] = bech32_charset[(chk >> ((5 - i) * 5)) & 0x1f];

  dst[j] = '\0';

  if (dstlen)
    *dstlen = j;

  return 1;
}

int
bech32_deserialize(char *hrp,
                   size_t *hrplen,
                   uint8_t *dst,
                   size_t *dstlen,
                   const char *src,
                   size_t srclen) {
  size_t hlen = srclen;
  uint32_t chk = 1;
  int lower = 0;
  int upper = 0;
  size_t j = 0;
  size_t i;

  if (srclen < 7 || srclen > BECH32_MAX_SERIALIZE_SIZE)
    return 0;

  while (hlen > 0 && src[hlen - 1] != '1')
    hlen -= 1;

  if (hlen == 0)
    return 0;

  hlen -= 1;

  if (srclen - (hlen + 1) < 6)
    return 0;

  for (i = 0; i < hlen; i++) {
    uint8_t ch = src[i];

    if (ch < 33 || ch > 126)
      return 0;

    if (ch >= 97 && ch <= 122) {
      lower = 1;
    } else if (ch >= 65 && ch <= 90) {
      upper = 1;
      ch += 32;
    }

    chk = bech32_polymod(chk) ^ (ch >> 5);

    hrp[i] = ch;
  }

  hrp[i] = '\0';

  chk = bech32_polymod(chk);

  for (i = 0; i < hlen; i++)
    chk = bech32_polymod(chk) ^ (src[i] & 0x1f);

  i += 1;

  while (i < srclen) {
    uint8_t ch = src[i];
    uint8_t val;

    if (ch & 0x80)
      return 0;

    val = bech32_table[ch];

    if (val & 0x80)
      return 0;

    if (ch >= 97 && ch <= 122)
      lower = 1;
    else if (ch >= 65 && ch <= 90)
      upper = 1;

    chk = bech32_polymod(chk) ^ val;

    if (i < srclen - 6)
      dst[j++] = val;

    i += 1;
  }

  if (lower && upper)
    return 0;

  if (chk != 1)
    return 0;

  if (hrplen)
    *hrplen = hlen;

  if (dstlen)
    *dstlen = j;

  return 1;
}

int
bech32_is(const char *str, size_t len) {
  char hrp[BECH32_MAX_HRP_SIZE + 1];
  uint8_t data[BECH32_MAX_DESERIALIZE_SIZE];

  return bech32_deserialize(hrp, NULL, data, NULL, str, len);
}

int
bech32_convert_bits(uint8_t *dst,
                    size_t *dstlen,
                    size_t dstbits,
                    const uint8_t *src,
                    size_t srclen,
                    size_t srcbits,
                    int pad) {
  uint32_t mask = (UINT32_C(1) << dstbits) - 1;
  uint32_t acc = 0;
  size_t bits = 0;
  size_t j = 0;
  size_t i, left;

  for (i = 0; i < srclen; i++) {
    acc = (acc << srcbits) | src[i];
    bits += srcbits;

    while (bits >= dstbits) {
      bits -= dstbits;
      dst[j++] = (acc >> bits) & mask;
    }
  }

  left = dstbits - bits;

  if (pad) {
    if (bits)
      dst[j++] = (acc << left) & mask;
  } else {
    if (((acc << left) & mask) || bits >= srcbits)
      return 0;
  }

  if (dstlen)
    *dstlen = j;

  return 1;
}

int
bech32_encode(char *out,
              size_t *out_len,
              const char *hrp,
              size_t hrp_len,
              unsigned int version,
              const uint8_t *hash,
              size_t hash_len) {
  uint8_t data[BECH32_MAX_DATA_SIZE];
  size_t data_len;

  if (version > BECH32_MAX_VERSION)
    return 0;

  if (hash_len < BECH32_MIN_HASH_SIZE
      || hash_len > BECH32_MAX_HASH_SIZE) {
    return 0;
  }

  data[0] = version;

  if (!bech32_convert_bits(data + 1, &data_len, 5,
                           hash, hash_len, 8, 1)) {
    return 0;
  }

  data_len += 1;

  return bech32_serialize(out, out_len, hrp, hrp_len, data, data_len);
}

int
bech32_decode(char *hrp,
              size_t *hrp_len,
              unsigned int *version,
              uint8_t *hash,
              size_t *hash_len,
              const char *str,
              size_t str_len) {
  uint8_t data[BECH32_MAX_DESERIALIZE_SIZE];
  size_t data_len;

  if (!bech32_deserialize(hrp, hrp_len, data, &data_len, str, str_len))
    return 0;

  if (data_len == 0 || data_len > BECH32_MAX_DATA_SIZE)
    return 0;

  if (data[0] > BECH32_MAX_VERSION)
    return 0;

  if (!bech32_convert_bits(hash, hash_len, 8,
                           data + 1, data_len - 1, 5, 0)) {
    return 0;
  }

  if (*hash_len < BECH32_MIN_HASH_SIZE
      || *hash_len > BECH32_MAX_HASH_SIZE) {
    return 0;
  }

  *version = data[0];

  return 1;
}

int
bech32_test(const char *str, size_t len) {
  char hrp[BECH32_MAX_HRP_SIZE + 1];
  unsigned int version;
  uint8_t hash[BECH32_MAX_DECODE_SIZE];
  size_t hash_len;

  return bech32_decode(hrp, NULL, &version, hash, &hash_len, str, len);
}

/*
 * Cash32
 *
 * Resources:
 *   https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
 *   https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/cashaddr.cpp
 *   https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/cashaddrenc.cpp
 *   https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/util/strencodings.h
 */

static const char *cash32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t cash32_table[128] = {
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30,
   7,  5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8,
  23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,
   6,  4,  2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8,
  23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,
   6,  4,  2, -1, -1, -1, -1, -1
};

static uint64_t
cash32_polymod(uint64_t pre) {
  uint64_t b = pre >> 35;

  return ((pre & UINT64_C(0x07ffffffff)) << 5)
    ^ (UINT64_C(0x98f2bc8e61) & -((b >> 0) & 1))
    ^ (UINT64_C(0x79b76d99e2) & -((b >> 1) & 1))
    ^ (UINT64_C(0xf33e5fb3c4) & -((b >> 2) & 1))
    ^ (UINT64_C(0xae2eabe2a8) & -((b >> 3) & 1))
    ^ (UINT64_C(0x1e4f43e470) & -((b >> 4) & 1));
}

int
cash32_serialize(char *dst,
                 size_t *dstlen,
                 const char *pre,
                 size_t prelen,
                 const uint8_t *src,
                 size_t srclen) {
  uint64_t chk = 1;
  size_t j = 0;
  size_t i;

  if (prelen == 0 || prelen > CASH32_MAX_PREFIX_SIZE)
    return 0;

  if (srclen > CASH32_MAX_DATA_SIZE)
    return 0;

  for (i = 0; i < prelen; i++) {
    uint8_t ch = pre[i];

    if (ch < 33 || ch > 126)
      return 0;

    if (ch >= 65 && ch <= 90)
      return 0;

    if (ch >= 48 && ch <= 57)
      return 0;

    if (ch == 58)
      return 0;

    chk = cash32_polymod(chk) ^ (ch & 0x1f);

    dst[j++] = ch;
  }

  chk = cash32_polymod(chk);

  dst[j++] = ':';

  for (i = 0; i < srclen; i++) {
    uint8_t ch = src[i];

    if (ch >> 5)
      return 0;

    chk = cash32_polymod(chk) ^ ch;

    dst[j++] = cash32_charset[ch];
  }

  for (i = 0; i < 8; i++)
    chk = cash32_polymod(chk);

  chk ^= 1;

  for (i = 0; i < 8; i++)
    dst[j++] = cash32_charset[(chk >> ((7 - i) * 5)) & 0x1f];

  dst[j] = '\0';

  if (dstlen)
    *dstlen = j;

  return 1;
}

int
cash32_deserialize(uint8_t *dst,
                   size_t *dstlen,
                   const char *src,
                   size_t srclen,
                   const char *pre,
                   size_t prelen) {
  size_t dlen = srclen;
  uint64_t chk = 1;
  int lower = 0;
  int upper = 0;
  size_t j = 0;
  size_t i;

  if (prelen == 0 || prelen > CASH32_MAX_PREFIX_SIZE)
    return 0;

  if (srclen < 8 || srclen > CASH32_MAX_SERIALIZE_SIZE)
    return 0;

  if (srclen > prelen && src[prelen] == ':')
    dlen = srclen - (prelen + 1);

  if (dlen < 8 || dlen > 112)
    return 0;

  if (dlen != srclen) {
    for (i = 0; i < prelen; i++) {
      uint8_t ch = src[i];

      if (ch >= 97 && ch <= 122) {
        lower = 1;
      } else if (ch >= 65 && ch <= 90) {
        upper = 1;
        ch += 32;
      }

      if (ch != (uint8_t)pre[i])
        return 0;
    }
  }

  for (i = 0; i < prelen; i++) {
    uint8_t ch = pre[i];

    if (ch < 33 || ch > 126)
      return 0;

    if (ch >= 65 && ch <= 90)
      return 0;

    if (ch >= 48 && ch <= 57)
      return 0;

    if (ch == 58)
      return 0;

    chk = cash32_polymod(chk) ^ (ch & 0x1f);
  }

  chk = cash32_polymod(chk);

  for (i = srclen - dlen; i < srclen; i++) {
    uint8_t ch = src[i];
    uint8_t val;

    if (ch & 0x80)
      return 0;

    val = cash32_table[ch];

    if (val & 0x80)
      return 0;

    if (ch >= 97 && ch <= 122)
      lower = 1;
    else if (ch >= 65 && ch <= 90)
      upper = 1;

    chk = cash32_polymod(chk) ^ val;

    if (i < srclen - 8)
      dst[j++] = val;
  }

  if (lower && upper)
    return 0;

  if (chk != 1)
    return 0;

  if (dstlen)
    *dstlen = j;

  return 1;
}

int
cash32_is(const char *str, size_t strlen, const char *pre, size_t prelen) {
  uint8_t data[CASH32_MAX_DESERIALIZE_SIZE];

  return cash32_deserialize(data, NULL, str, strlen, pre, prelen);
}

int
cash32_convert_bits(uint8_t *dst,
                    size_t *dstlen,
                    size_t dstbits,
                    const uint8_t *src,
                    size_t srclen,
                    size_t srcbits,
                    int pad) {
  size_t mask = ((size_t)1 << dstbits) - 1;
  size_t maxacc = ((size_t)1 << (srcbits + dstbits - 1)) - 1;
  size_t acc = 0;
  size_t bits = 0;
  size_t j = 0;
  size_t i, left;

  for (i = 0; i < srclen; i++) {
    acc = ((acc << srcbits) | src[i]) & maxacc;
    bits += srcbits;

    while (bits >= dstbits) {
      bits -= dstbits;
      dst[j++] = (acc >> bits) & mask;
    }
  }

  left = dstbits - bits;

  if (pad) {
    if (bits)
      dst[j++] = (acc << left) & mask;
  } else {
    if (bits >= srcbits || ((acc << left) & mask))
      return 0;
  }

  if (dstlen)
    *dstlen = j;

  return 1;
}

int
cash32_encode(char *out,
              size_t *out_len,
              const char *pre,
              size_t pre_len,
              unsigned int type,
              const uint8_t *hash,
              size_t hash_len) {
  uint8_t conv[CASH32_MAX_DATA_SIZE];
  uint8_t data[1 + CASH32_MAX_HASH_SIZE];
  size_t conv_len, size;

  if (type > CASH32_MAX_TYPE)
    return 0;

  switch (hash_len * 8) {
    case 160:
      size = 0;
      break;
    case 192:
      size = 1;
      break;
    case 224:
      size = 2;
      break;
    case 256:
      size = 3;
      break;
    case 320:
      size = 4;
      break;
    case 384:
      size = 5;
      break;
    case 448:
      size = 6;
      break;
    case 512:
      size = 7;
      break;
    default:
      return 0;
  }

  data[0] = (type << 3) | size;

  memcpy(data + 1, hash, hash_len);

  if (!cash32_convert_bits(conv, &conv_len, 5, data, hash_len + 1, 8, 1))
    return 0;

  return cash32_serialize(out, out_len, pre, pre_len, conv, conv_len);
}

int
cash32_decode(unsigned int *type,
              uint8_t *hash,
              size_t *hash_len,
              const char *str,
              size_t str_len,
              const char *pre,
              size_t pre_len) {
  uint8_t conv[CASH32_MAX_DESERIALIZE_SIZE];
  uint8_t data[1 + CASH32_MAX_HASH_SIZE];
  size_t data_len, conv_len, size;

  if (!cash32_deserialize(conv, &conv_len, str, str_len, pre, pre_len))
    return 0;

  if (conv_len == 0 || conv_len > CASH32_MAX_DATA_SIZE)
    return 0;

  if (!cash32_convert_bits(data, &data_len, 8, conv, conv_len, 5, 0))
    return 0;

  if (data_len == 0 || data_len > 1 + CASH32_MAX_HASH_SIZE)
    return 0;

  *type = (data[0] >> 3) & 31;
  *hash_len = data_len - 1;

  memcpy(hash, data + 1, *hash_len);

  size = CASH32_MIN_HASH_SIZE + 4 * (data[0] & 3);

  if (data[0] & 4)
    size *= 2;

  if (*type > CASH32_MAX_TYPE)
    return 0;

  if (size != *hash_len)
    return 0;

  return 1;
}

int
cash32_test(const char *str, size_t str_len, const char *pre, size_t pre_len) {
  uint8_t hash[CASH32_MAX_DECODE_SIZE];
  size_t hash_len;
  unsigned int type;

  return cash32_decode(&type, hash, &hash_len, str, str_len, pre, pre_len);
}
