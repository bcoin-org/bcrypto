/* Copyright (c) 2018 the bcoin developers
 * Copyright (c) 2017 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef _BCRYPTO_CASHADDR_H
#define _BCRYPTO_CASHADDR_H 1

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef enum bcrypto_cashaddr_error_t {
  bcrypto_cashaddr_ERR_NULL = 0,
  bcrypto_cashaddr_ERR_CHECKSUM,
  bcrypto_cashaddr_ERR_LENGTH,
  bcrypto_cashaddr_ERR_CASING,
  bcrypto_cashaddr_ERR_PADDING,
  bcrypto_cashaddr_ERR_NONZERO_PADDING,
  bcrypto_cashaddr_ERR_CHARACTER,
  bcrypto_cashaddr_ERR_PREFIX,
  bcrypto_cashaddr_ERR_TYPE,
  bcrypto_cashaddr_ERR_SIZE,
  bcrypto_cashaddr_ERR_SEPARATOR
} bcrypto_cashaddr_error;

int
bcrypto_cashaddr_encode(
  bcrypto_cashaddr_error *err,
  char *output,
  const char *prefix,
  int type,
  const uint8_t *hash,
  size_t hash_len
);

int
bcrypto_cashaddr_decode(
  bcrypto_cashaddr_error *err,
  int* type,
  uint8_t* hash,
  size_t* hash_len,
  char* prefix,
  const char* default_prefix,
  const char* addr
);

int
bcrypto_cashaddr_test(
  bcrypto_cashaddr_error *err,
  const char *default_prefix,
  const char *addr
);

const char *
bcrypto_cashaddr_strerror(bcrypto_cashaddr_error err);

#if defined(__cplusplus)
}
#endif

#endif
