#ifndef _BCRYPTO_CIPHER_H
#define _BCRYPTO_CIPHER_H

#define BCRYPTO_ENCIPHER_SIZE(len) ((len) + (16 - ((len) % 16)));
#define BCRYPTO_DECIPHER_SIZE(len) (len)

#ifdef BCRYPTO_USE_CIPHER
bool
bcrypto_cipher(
  const char *name,
  const uint8_t *data,
  const uint32_t datalen,
  const uint8_t *key,
  const uint32_t keylen,
  const uint8_t *iv,
  const uint32_t ivlen,
  uint8_t **out,
  uint32_t *outlen,
  const bool encrypt
);
#endif

bool
bcrypto_encipher(
  const uint8_t *data,
  const uint32_t datalen,
  const uint8_t *key,
  const uint8_t *iv,
  uint8_t *out,
  uint32_t *outlen
);

bool
bcrypto_decipher(
  const uint8_t *data,
  const uint32_t datalen,
  const uint8_t *key,
  const uint8_t *iv,
  uint8_t *out,
  uint32_t *outlen
);
#endif
