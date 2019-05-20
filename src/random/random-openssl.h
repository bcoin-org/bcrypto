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

void
bcrypto_rng(void *ctx, size_t length, uint8_t *dst) {
  assert(bcrypto_random((void *)dst, length) != 0);
}
