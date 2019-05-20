#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include "random.h"

#ifdef BCRYPTO_WITH_OPENSSL
#include "openssl/rand.h"

void
bcrypto_random_seed(const void *data, size_t len) {}

uint32_t
bcrypto_random_calls(void) {
  return 0;
}

void
bcrypto_random_poll(void) {
  for (;;) {
    // https://github.com/openssl/openssl/blob/bc420eb/crypto/rand/rand_lib.c#L792
    // https://github.com/openssl/openssl/blob/bc420eb/crypto/rand/drbg_lib.c#L988
    int status = RAND_status();

    assert(status >= 0);

    if (status != 0)
      break;

    // https://github.com/openssl/openssl/blob/bc420eb/crypto/rand/rand_lib.c#L376
    // https://github.com/openssl/openssl/blob/32f803d/crypto/rand/drbg_lib.c#L471
    if (RAND_poll() == 0)
      break;
  }
}

int
bcrypto_random(void *dst, size_t len) {
  bcrypto_random_poll();

  return RAND_bytes((unsigned char *)dst, (int)len) == 1;
}
#else
#include "../nettle/yarrow.h"
#include <mutex>

static std::mutex m;
static struct yarrow256_ctx rng;
static uint32_t calls = 0; /* okay to overflow */

void
bcrypto_random_seed(const void *data, size_t len) {
  m.lock();

  if (len > 0) {
    if (calls == 0) {
      yarrow256_init(&rng, 0, NULL);
      calls = 1;
    }

    yarrow256_seed(&rng, len, (const uint8_t *)data);
  }

  m.unlock();
}

uint32_t
bcrypto_random_calls(void) {
  m.lock();

  uint32_t r = calls;

  m.unlock();
  return r;
}

void
bcrypto_random_poll(void) {}

int
bcrypto_random(void *dst, size_t len) {
  int result = 0;

  m.lock();

  if (calls == 0)
    goto fail;

  yarrow256_random(&rng, len, (uint8_t *)dst);
  calls += 1;

  result = 1;
fail:
  m.unlock();
  return result;
}
#endif

void
bcrypto_rng(void *ctx, size_t length, uint8_t *dst) {
  assert(bcrypto_random((void *)dst, length) != 0);
}
