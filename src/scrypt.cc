#include "scrypt.h"

extern "C" {
#include "scrypt/crypto_scrypt.h"
}

bool
bcrypto_scrypt(
  const uint8_t *pass,
  const uint32_t passlen,
  const uint8_t *salt,
  size_t saltlen,
  uint64_t N,
  uint64_t r,
  uint64_t p,
  uint8_t *key,
  size_t keylen
) {
  int32_t result = crypto_scrypt(
    pass, passlen, salt, saltlen,
    N, r, p, key, keylen);

  return result == 0;
}
