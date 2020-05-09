/*!
 * bech32.c - bech32 for bcrypto
 * Copyright (c) 2017-2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on sipa/bech32:
 *   Copyright (c) 2017, Pieter Wuille (MIT License).
 *   https://github.com/sipa/bech32
 *
 * Resources:
 *   https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
 *   https://github.com/sipa/bech32/blob/master/ref/c/segwit_addr.c
 *   https://github.com/bitcoin/bitcoin/blob/master/src/bech32.cpp
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "bech32.h"

/*
 * Constants
 */

static const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t TABLE[128] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

/*
 * Helpers
 */

static uint32_t
polymod_step(uint32_t pre) {
  uint8_t b = pre >> 25;
  return ((pre & UINT32_C(0x1ffffff)) << 5)
    ^ (-((b >> 0) & 1) & UINT32_C(0x3b6a57b2))
    ^ (-((b >> 1) & 1) & UINT32_C(0x26508e6d))
    ^ (-((b >> 2) & 1) & UINT32_C(0x1ea119fa))
    ^ (-((b >> 3) & 1) & UINT32_C(0x3d4233dd))
    ^ (-((b >> 4) & 1) & UINT32_C(0x2a1462b3));
}

/*
 * Bech32
 */

int
bech32_serialize(char *out,
                 const char *hrp,
                 const uint8_t *data,
                 size_t data_len) {
  uint32_t chk = 1;
  size_t i = 0;

  while (hrp[i] != 0) {
    int ch = hrp[i];

    if (ch < 33 || ch > 126)
      return 0;

    if (ch >= 'A' && ch <= 'Z')
      return 0;

    chk = polymod_step(chk) ^ (ch >> 5);
    i += 1;
  }

  if (i + 7 + data_len > 90)
    return 0;

  chk = polymod_step(chk);

  while (*hrp != 0) {
    chk = polymod_step(chk) ^ (*hrp & 0x1f);
    *(out++) = *(hrp++);
  }

  *(out++) = '1';

  for (i = 0; i < data_len; i++) {
    if (*data >> 5)
      return 0;

    chk = polymod_step(chk) ^ (*data);
    *(out++) = CHARSET[*(data++)];
  }

  for (i = 0; i < 6; i++)
    chk = polymod_step(chk);

  chk ^= 1;

  for (i = 0; i < 6; i++)
    *(out++) = CHARSET[(chk >> ((5 - i) * 5)) & 0x1f];

  *out = 0;

  return 1;
}

int
bech32_deserialize(char *hrp,
                   uint8_t *data,
                   size_t *data_len,
                   const char *input) {
  size_t input_len = strlen(input);
  int have_lower = 0;
  int have_upper = 0;
  uint32_t chk = 1;
  size_t hrp_len;
  size_t i;

  if (input_len < 8 || input_len > 90)
    return 0;

  *data_len = 0;

  while (*data_len < input_len && input[(input_len - 1) - *data_len] != '1')
    (*data_len) += 1;

  hrp_len = input_len - (1 + *data_len);

  if (1 + *data_len >= input_len || *data_len < 6)
    return 0;

  *(data_len) -= 6;

  for (i = 0; i < hrp_len; i++) {
    int ch = input[i];

    if (ch < 33 || ch > 126)
      return 0;

    if (ch >= 'a' && ch <= 'z') {
      have_lower = 1;
    } else if (ch >= 'A' && ch <= 'Z') {
      have_upper = 1;
      ch = (ch - 'A') + 'a';
    }

    hrp[i] = ch;
    chk = polymod_step(chk) ^ (ch >> 5);
  }

  hrp[i] = 0;

  chk = polymod_step(chk);

  for (i = 0; i < hrp_len; i++)
    chk = polymod_step(chk) ^ (input[i] & 0x1f);

  i += 1;

  while (i < input_len) {
    int v = (input[i] & 0x80) ? -1 : TABLE[(int)input[i]];

    if (input[i] >= 'a' && input[i] <= 'z')
      have_lower = 1;

    if (input[i] >= 'A' && input[i] <= 'Z')
      have_upper = 1;

    if (v == -1)
      return 0;

    chk = polymod_step(chk) ^ v;

    if (i + 6 < input_len)
      data[i - (1 + hrp_len)] = v;

    i += 1;
  }

  if (have_lower && have_upper)
    return 0;

  return chk == 1;
}

int
bech32_is(const char *str) {
  char hrp[84];
  uint8_t data[84];
  size_t data_len;

  if (!bech32_deserialize(hrp, data, &data_len, str))
    return 0;

  return 1;
}

int
bech32_convert_bits(uint8_t *out,
                    size_t *outlen,
                    int outbits,
                    const uint8_t *in,
                    size_t inlen,
                    int inbits,
                    int pad) {
  uint32_t maxv = (((uint32_t)1) << outbits) - 1;
  uint32_t val = 0;
  int bits = 0;

  while (inlen--) {
    val = (val << inbits) | *(in++);
    bits += inbits;
    while (bits >= outbits) {
      bits -= outbits;
      out[(*outlen)++] = (val >> bits) & maxv;
    }
  }

  if (pad) {
    if (bits)
      out[(*outlen)++] = (val << (outbits - bits)) & maxv;
  } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
    return 0;
  }

  return 1;
}

int
bech32_encode(char *out,
              const char *hrp,
              int version,
              const uint8_t *hash,
              size_t hash_len) {
  uint8_t data[65];
  size_t data_len = 0;

  if (version < 0 || version > 31)
    return 0;

  if (hash_len < 2 || hash_len > 40)
    return 0;

  data[0] = version;

  if (!bech32_convert_bits(data + 1, &data_len, 5,
                           hash, hash_len, 8, 1)) {
    return 0;
  }

  data_len += 1;

  return bech32_serialize(out, hrp, data, data_len);
}

int
bech32_decode(char *hrp,
              int *version,
              uint8_t *hash,
              size_t *hash_len,
              const char *str) {
  uint8_t data[84];
  size_t data_len;

  if (!bech32_deserialize(hrp, data, &data_len, str))
    return 0;

  if (data_len == 0 || data_len > 65)
    return 0;

  if (data[0] > 31)
    return 0;

  *hash_len = 0;

  if (!bech32_convert_bits(hash, hash_len, 8,
                           data + 1, data_len - 1, 5, 0)) {
    return 0;
  }

  if (*hash_len < 2 || *hash_len > 40)
    return 0;

  *version = data[0];

  return 1;
}

int
bech32_test(const char *str) {
  char hrp[84];
  uint8_t data[84];
  size_t data_len;

  if (!bech32_deserialize(hrp, data, &data_len, str))
    return 0;

  if (data_len == 0 || data_len > 65)
    return 0;

  if (data[0] > 31)
    return 0;

  return 1;
}
