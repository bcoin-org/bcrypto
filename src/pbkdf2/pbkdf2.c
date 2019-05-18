#include <string.h>
#include <limits.h>
#include "pbkdf2.h"
#include "../hash/hash.h"
#include "../nettle/pbkdf2.h"

int
bcrypto_pbkdf2(uint8_t *key,
               int type,
               const uint8_t *pass,
               size_t passlen,
               const uint8_t *salt,
               size_t saltlen,
               uint32_t iter,
               size_t keylen) {
  const struct nettle_hash *hash = bcrypto_hash_get(type);

  if (hash == NULL)
    return 0;

  if (passlen > (size_t)INT_MAX
      || saltlen > (size_t)INT_MAX
      || (size_t)iter > (size_t)INT_MAX
      || keylen > (size_t)INT_MAX) {
    return 0;
  }

  bcrypto_hmac_t hmac;

  hmac.hash = hash;

  bcrypto_hmac_set_key(&hmac, passlen, pass);

  PBKDF2(&hmac, bcrypto_hmac_update, bcrypto_hmac_digest,
         hash->digest_size, iter, saltlen, salt, keylen, key);

  return 1;
}

int
bcrypto_pbkdf2_has_hash(int type) {
  return bcrypto_hash_get(type) != NULL;
}
