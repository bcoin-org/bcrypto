/*!
 * bech32.h - bech32 for bcrypto
 * Copyright (c) 2017-2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on sipa/bech32:
 *   Copyright (c) 2017, Pieter Wuille (MIT License).
 *   https://github.com/sipa/bech32
 */

#ifndef _BCRYPTO_BECH32_H
#define _BCRYPTO_BECH32_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * Symbol Aliases
 */

#define bech32_serialize _bcrypto_bech32_serialize
#define bech32_deserialize _bcrypto_bech32_deserialize
#define bech32_is _bcrypto_bech32_is
#define bech32_convert_bits _bcrypto_bech32_convert_bits
#define bech32_encode _bcrypto_bech32_encode
#define bech32_decode _bcrypto_bech32_decode
#define bech32_test _bcrypto_bech32_test

/*
 * Bech32
 */

int
bech32_serialize(char *out,
                 const char *hrp,
                 const uint8_t *data,
                 size_t data_len);

int
bech32_deserialize(char *hrp,
                   uint8_t *data,
                   size_t *data_len,
                   const char *input);

int
bech32_is(const char *str);

int
bech32_convert_bits(uint8_t *out,
                    size_t *outlen,
                    int outbits,
                    const uint8_t *in,
                    size_t inlen,
                    int inbits,
                    int pad);

int
bech32_encode(char *out,
              const char *hrp,
              int version,
              const uint8_t *hash,
              size_t hash_len);

int
bech32_decode(char *hrp,
              int *version,
              uint8_t *hash,
              size_t *hash_len,
              const char *str);

int
bech32_test(const char *str);

#ifdef __cplusplus
}
#endif

#endif
