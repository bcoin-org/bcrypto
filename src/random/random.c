#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "openssl/rand.h"
#include "random.h"

bool
bcrypto_random(uint8_t *dst, size_t len) {
  for (;;) {
    int status = RAND_status();

    if (status == 1)
      break;

    if (RAND_poll() == 1)
      break;
  }

  int r = RAND_bytes(dst, len);

  if (r != 1)
    return false;

  return true;
}
