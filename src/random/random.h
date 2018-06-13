#ifndef _BCRYPTO_RANDOM_H
#define _BCRYPTO_RANDOM_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

bool
bcrypto_random(uint8_t *dst, size_t len);

#if defined(__cplusplus)
}
#endif

#endif
