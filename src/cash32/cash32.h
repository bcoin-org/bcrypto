/*!
 * cash32.h - cashaddr for bcrypto
 * Copyright (c) 2018-2020, The Bcoin Developers (MIT License).
 * https://github.com/bcoin-org/bcrypto
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

#ifndef _BCRYPTO_CASH32_H
#define _BCRYPTO_CASH32_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * Symbol Aliases
 */

#define cash32_serialize _bcrypto_cash32_serialize
#define cash32_deserialize _bcrypto_cash32_deserialize
#define cash32_is _bcrypto_cash32_is
#define cash32_convert_bits _bcrypto_cash32_convert_bits
#define cash32_encode _bcrypto_cash32_encode
#define cash32_decode _bcrypto_cash32_decode
#define cash32_test _bcrypto_cash32_test

/*
 * Cash32
 */

int
cash32_serialize(char *out,
                 const char *prefix,
                 const uint8_t *data,
                 size_t data_len);

int
cash32_deserialize(char *prefix,
                   uint8_t *data,
                   size_t *data_len,
                   const char *default_prefix,
                   const char *input);

int
cash32_is(const char *default_prefix,
          const char *addr);

int
cash32_convert_bits(uint8_t *out,
                    size_t *outlen,
                    int outbits,
                    const uint8_t *in,
                    size_t inlen,
                    int inbits,
                    int pad);

int
cash32_encode(char *out,
              const char *prefix,
              int type,
              const uint8_t *hash,
              size_t hash_len);

int
cash32_decode(char *prefix,
              int *type,
              uint8_t *hash,
              size_t *hash_len,
              const char *default_prefix,
              const char *addr);

int
cash32_test(const char *default_prefix,
            const char *addr);

#ifdef __cplusplus
}
#endif

#endif
