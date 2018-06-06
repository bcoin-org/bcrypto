#include "pbkdf2.h"
#include "openssl/evp.h"

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
) {
  const EVP_MD* md = EVP_get_digestbyname(name);

  if (md == NULL)
    return false;

  uint32_t ret = PKCS5_PBKDF2_HMAC(
    (const char *)data, datalen, salt,
    saltlen, iter, md, keylen, key);

  if (ret <= 0)
    return false;

  return true;
}
