/*!
 * base58.c - base58 for bcrypto
 * Copyright (c) 2016-2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "base58.h"

/*
 * Constants
 */

static const char CHARSET[58 + 1] =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int TABLE[128] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
  -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
  22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
  -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
  47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1
};

/*
 * Base58
 */

static void
_base58_encode(char *str, size_t *str_len,
               const uint8_t *data, size_t data_len,
               uint8_t *b58, size_t b58len) {
  size_t zeroes = 0;
  size_t length = 0;
  size_t i, j, k;
  unsigned long carry;

  for (i = 0; i < data_len; i++) {
    if (data[i] != 0)
      break;

    zeroes += 1;
  }

  memset(b58, 0, b58len);

  for (; i < data_len; i++) {
    carry = data[i];

    for (j = 0, k = b58len - 1; j < b58len; j++, k--) {
      if (carry == 0 && j >= length)
        break;

      carry += (unsigned long)b58[k] << 8;
      b58[k] = carry % 58;
      carry /= 58;
    }

    assert(carry == 0);

    length = j;
  }

  i = b58len - length;

  while (i < b58len && b58[i] == 0)
    i += 1;

  assert(*str_len >= zeroes + (b58len - i));

  for (j = 0; j < zeroes; j++)
    str[j] = '1';

  while (i < b58len)
    str[j++] = CHARSET[b58[i++]];

  str[j] = '\0';
  *str_len = j;
}

static int
_base58_decode(uint8_t *data, size_t *data_len,
               const char *str, size_t str_len,
               uint8_t *b256, size_t b256len) {
  size_t zeroes = 0;
  size_t length = 0;
  size_t i, j, k;
  unsigned long carry;
  uint8_t ch;
  int val;

  for (i = 0; i < str_len; i++) {
    if (str[i] != '1')
      break;

    zeroes += 1;
  }

  memset(b256, 0, b256len);

  for (; i < str_len; i++) {
    ch = str[i];

    if (ch & 0x80)
      return 0;

    val = TABLE[ch];

    if (val == -1)
      return 0;

    carry = val;

    for (j = 0, k = b256len - 1; j < b256len; j++, k--) {
      if (carry == 0 && j >= length)
        break;

      carry += (unsigned long)b256[k] * 58;
      b256[k] = carry;
      carry >>= 8;
    }

    assert(carry == 0);

    length = j;
  }

  i = 0;

  while (i < b256len && b256[i] == 0)
    i += 1;

  assert(*data_len >= zeroes + (b256len - i));

  for (j = 0; j < zeroes; j++)
    data[j] = 0;

  while (i < b256len)
    data[j++] = b256[i++];

  *data_len = j;

  return 1;
}

static int
_base58_test(const char *str, size_t str_len) {
  size_t i = 0;
  uint8_t ch;

  for (; i < str_len; i++) {
    ch = str[i];

    if (ch & 0x80)
      return 0;

    if (TABLE[ch] == -1)
      return 0;
  }

  return 1;
}

/*
 * Base58 (arbitrary length)
 */

int
base58_encode(char *str, size_t *str_len,
              const unsigned char *data, size_t data_len) {
  size_t b58len;
  uint8_t *b58;

  if (data_len > BASE58_DATA_MAX)
    return 0;

  b58len = BASE58_STRING_ITCH(data_len);
  b58 = malloc(b58len);

  if (b58 == NULL)
    return 0;

  _base58_encode(str, str_len, data, data_len, b58, b58len);

  free(b58);

  return 1;
}

int
base58_decode(unsigned char *data, size_t *data_len,
              const char *str, size_t str_len) {
  size_t b256len;
  uint8_t *b256;
  int ret;

  if (str_len > BASE58_STRING_MAX)
    return 0;

  b256len = BASE58_DATA_ITCH(str_len);
  b256 = malloc(b256len);

  if (b256 == NULL)
    return 0;

  ret = _base58_decode(data, data_len, str, str_len, b256, b256len);

  free(b256);

  return ret;
}

int
base58_test(const char *str, size_t str_len) {
  if (str_len > BASE58_STRING_MAX)
    return 0;

  return _base58_test(str, str_len);
}

/*
 * Base58 (length <= 1024)
 */

int
base58_encode_1024(char *str, size_t *str_len,
                   const unsigned char *data, size_t data_len) {
  uint8_t b58[BASE58_STRING_ITCH_1024];
  size_t b58len;

  if (data_len > BASE58_DATA_MAX_1024)
    return 0;

  b58len = BASE58_STRING_ITCH(data_len);

  assert(b58len <= sizeof(b58));

  _base58_encode(str, str_len, data, data_len, b58, b58len);

  return 1;
}

int
base58_decode_1024(unsigned char *data, size_t *data_len,
                   const char *str, size_t str_len) {
  uint8_t b256[BASE58_DATA_ITCH_1024];
  size_t b256len;

  if (str_len > BASE58_STRING_MAX_1024)
    return 0;

  b256len = BASE58_DATA_ITCH(str_len);

  assert(b256len <= sizeof(b256));

  return _base58_decode(data, data_len, str, str_len, b256, b256len);
}

int
base58_test_1024(const char *str, size_t str_len) {
  if (str_len > BASE58_STRING_MAX_1024)
    return 0;

  return _base58_test(str, str_len);
}
