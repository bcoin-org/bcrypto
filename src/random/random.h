#ifndef _BCRYPTO_RANDOM_H
#define _BCRYPTO_RANDOM_H

#include <stdlib.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

void
bcrypto_random_seed(const void *data, size_t len);

uint32_t
bcrypto_random_calls(void);

int
bcrypto_random(void *dst, size_t len);

void
bcrypto_rng(void *ctx, size_t length, uint8_t *dst);

#if defined(__cplusplus)
}
#endif

#endif
