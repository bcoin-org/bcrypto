/*!
 * base58.h - base58 for bcrypto
 * Copyright (c) 2016-2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

#ifndef _BCRYPTO_BASE58_H
#define _BCRYPTO_BASE58_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Symbol Aliases
 */

#define base58_encode _bcrypto_base58_encode
#define base58_decode _bcrypto_base58_decode
#define base58_test _bcrypto_base58_test
#define base58_encode_1024 _bcrypto_base58_encode_1024
#define base58_decode_1024 _bcrypto_base58_decode_1024
#define base58_test_1024 _bcrypto_base58_test_1024

/*
 * Definitions
 */

#define BASE58_DATA_MAX 0x7fffffff
#define BASE58_DATA_ITCH(n) ((uint64_t)(n) * 733 / 1000 + 1)
#define BASE58_DATA_MAX_1024 1024
#define BASE58_DATA_ITCH_1024 1026 /* 1399 * 733 / 1000 + 1 */

#define BASE58_STRING_MAX 0xffffffff
#define BASE58_STRING_ITCH(n) ((uint64_t)(n) * 138 / 100 + 1)
#define BASE58_STRING_MAX_1024 1399
#define BASE58_STRING_ITCH_1024 1414 /* 1024 * 138 / 100 + 1 */

/*
 * Base58 (arbitrary length)
 */

int
base58_encode(char *str, size_t *str_len,
              const unsigned char *data, size_t data_len);

int
base58_decode(unsigned char *data, size_t *data_len,
              const char *str, size_t str_len);

int
base58_test(const char *str, size_t str_len);

/*
 * Base58 (length <= 1024)
 */

int
base58_encode_1024(char *str, size_t *str_len,
                   const unsigned char *data, size_t data_len);

int
base58_decode_1024(unsigned char *data, size_t *data_len,
                   const char *str, size_t str_len);

int
base58_test_1024(const char *str, size_t str_len);

#ifdef __cplusplus
}
#endif

#endif
