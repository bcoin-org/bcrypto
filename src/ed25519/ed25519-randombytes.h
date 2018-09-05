#include "openssl/rand.h"

void
ED25519_FN(ed25519_randombytes_unsafe) (void *p, size_t len) {
  RAND_bytes(p, (int)len);
}
