/*!
 * murmur3.h - murmur3 for bcrypto
 * Copyright (c) 2016-2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

#ifndef _BCRYPTO_MURMUR3_H
#define _BCRYPTO_MURMUR3_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * Symbol Aliases
 */

#define murmur3_sum _bcrypto_murmur3_sum
#define murmur3_tweak _bcrypto_murmur3_tweak

/*
 * Murmur3
 */

uint32_t
murmur3_sum(const unsigned char *data, size_t len, uint32_t seed);

uint32_t
murmur3_tweak(const unsigned char *data,
              size_t len, uint32_t n, uint32_t tweak);

#if defined(__cplusplus)
}
#endif

#endif
