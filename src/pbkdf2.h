#ifndef _BCRYPTO_PBKDF2_H
#define _BCRYPTO_PBKDF2_H

#include <stdint.h>
#include <stdlib.h>

bool
bcrypto_pbkdf2(
  const char *name,
  const uint8_t *data,
  uint32_t datalen,
  const uint8_t *salt,
  uint32_t saltlen,
  uint32_t iter,
  uint8_t *key,
  uint32_t keylen
);

#endif
