#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include "random.h"

/* Our RNG passed in from javascript. */
extern int
_bcrypto_random(void *dst, size_t len);

void
bcrypto_random_seed(const void *data, size_t len) {}

uint32_t
bcrypto_random_calls(void) {
  return 0;
}

void
bcrypto_random_poll(void) {}

int
bcrypto_random(void *dst, size_t len) {
  return _bcrypto_random(dst, len);
}

void
bcrypto_rng(void *ctx, size_t length, uint8_t *dst) {
  assert(bcrypto_random((void *)dst, length) != 0);
}
