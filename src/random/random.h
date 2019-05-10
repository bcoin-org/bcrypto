#ifndef _BCRYPTO_RANDOM_H
#define _BCRYPTO_RANDOM_H

#include <stdlib.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

void
bcrypto_poll(void);

int
bcrypto_random(uint8_t *dst, size_t len);

#if defined(__cplusplus)
}
#endif

#endif
