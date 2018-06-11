#ifndef _BCRYPTO_ECDSA_H
#define _BCRYPTO_ECDSA_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

bool
bcrypto_ecdsa_generate(const char *name, uint8_t **priv, size_t *priv_len);

bool
bcrypto_ecdsa_create_pub(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **pub,
  size_t *pub_len
);

bool
bcrypto_ecdsa_convert_pub(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
);

bool
bcrypto_ecdsa_sign(
  const char *name,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *priv,
  size_t priv_len,
  uint8_t **r,
  size_t *r_len,
  uint8_t **s,
  size_t *s_len
);

bool
bcrypto_ecdsa_verify_priv(
  const char *name,
  const uint8_t *priv,
  size_t priv_len
);

bool
bcrypto_ecdsa_verify(
  const char *name,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *r,
  size_t r_len,
  const uint8_t *s,
  size_t s_len,
  const uint8_t *pub,
  size_t pub_len
);

bool
bcrypto_ecdsa_verify_pub(const char *name, const uint8_t *pub, size_t pub_len);

bool
bcrypto_ecdsa_ecdh(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **secret,
  size_t *secret_len
);

bool
bcrypto_ecdsa_tweak_priv(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  const uint8_t *tweak,
  size_t tweak_len,
  uint8_t **npriv,
  size_t *npriv_len
);

bool
bcrypto_ecdsa_tweak_pub(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  const uint8_t *tweak,
  size_t tweak_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
);

#if defined(__cplusplus)
}
#endif

#endif
