#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include "../nettle/yarrow.h"
#include "random.h"

static struct yarrow256_ctx rng;
static int initialized = 0;

void
bcrypto_seed(const void *data, size_t len) {
  if (initialized == 0) {
    yarrow256_init(&rng, 0, NULL);
    initialized = 1;
  }
  yarrow256_seed(&rng, len, (const uint8_t *)data);
}

void
bcrypto_poll(void) {}

int
bcrypto_random(void *dst, size_t len) {
  if (initialized == 0)
    return 0;
  yarrow256_random(&rng, len, (uint8_t *)dst);
  return 1;
}

void
bcrypto_rng(void *ctx, size_t length, uint8_t *dst) {
  assert(bcrypto_random((void *)dst, length) != 0);
}
