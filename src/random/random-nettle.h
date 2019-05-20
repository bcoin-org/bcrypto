#include "../nettle/yarrow.h"

#ifdef BCRYPTO_WASM
#define RNG_LOCK
#define RNG_UNLOCK
#else
#include <mutex>
static std::mutex m;
#define RNG_LOCK m.lock()
#define RNG_UNLOCK m.unlock()
#endif

static struct yarrow256_ctx rng;
static uint32_t calls = 0;

void
bcrypto_random_seed(const void *data, size_t len) {
  RNG_LOCK;

  if (calls == 0) {
    yarrow256_init(&rng, 0, NULL);
    calls = 1;
  }

  yarrow256_seed(&rng, len, (const uint8_t *)data);

  RNG_UNLOCK;
}

uint32_t
bcrypto_random_calls(void) {
  RNG_LOCK;

  uint32_t r = calls;

  RNG_UNLOCK;

  return r;
}

void
bcrypto_random_poll(void) {}

int
bcrypto_random(void *dst, size_t len) {
  RNG_LOCK;

  if (calls == 0)
    return 0;

  yarrow256_random(&rng, len, (uint8_t *)dst);
  calls += 1;

  RNG_UNLOCK;

  return 1;
}

void
bcrypto_rng(void *ctx, size_t length, uint8_t *dst) {
  assert(bcrypto_random((void *)dst, length) != 0);
}
