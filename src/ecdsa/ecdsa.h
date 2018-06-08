#ifndef _BCRYPTO_ECDSA_H
#define _BCRYPTO_ECDSA_H

#include <stdbool.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

bool
bcrypto_ecdsa_generate(const char *name, uint8_t **key, size_t *key_len);

bool
bcrypto_ecdsa_create_pub(
  const char *name,
  uint8_t *key,
  size_t key_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
);

bool
bcrypto_ecdsa_convert_pub(
  const char *name,
  uint8_t *key,
  size_t key_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
);

bool
bcrypto_ecdsa_sign(
  const char *name,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *key,
  size_t key_len,
  const uint8_t **sig,
  size_t *sig_len
);

bool
bcrypto_ecdsa_verify_priv(
  const char *name,
  const uint8_t *key,
  size_t key_len
);

bool
bcrypto_ecdsa_verify(
  const char *name,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *sig,
  size_t sig_len,
  const uint8_t *key,
  size_t key_len
);

bool
bcrypto_ecdsa_verify_pub(
  const char *name,
  const uint8_t *key,
  size_t key_len
);

bool
bcrypto_ecdsa_ecdh(
  const char *name,
  const uint8_t *privkey,
  size_t privkey_len,
  const uint8_t *pubkey,
  size_t pubkey_len,
  bool compress,
  const uint8_t **out,
  size_t *out_len
);

bool
bcrypto_ecdsa_tweak_priv(
  const char *name,
  const uint8_t *key,
  size_t key_len,
  const uint8_t *tweak,
  size_t tweak_len,
  const uint8_t **out,
  size_t *out_len
);

bool
bcrypto_ecdsa_tweak_pub(
  const char *name,
  const uint8_t *key,
  size_t key_len,
  const uint8_t *tweak,
  size_t tweak_len,
  bool compress,
  const uint8_t **out,
  size_t *out_len
);

bool
bcrypto_ecdsa_is_low_der(
  const char *name,
  const uint8_t *sig,
  size_t sig_len
);

#if defined(__cplusplus)
}
#endif

#endif
