#ifndef _BCRYPTO_SCRYPT_H
#define _BCRYPTO_SCRYPT_H

#include <stdint.h>
#include <stdlib.h>

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
);

#endif
