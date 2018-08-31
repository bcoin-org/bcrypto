#ifndef _BCRYPTO_DSA_H
#define _BCRYPTO_DSA_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct bcrypto_dsa_key_s {
  uint8_t *pd;
  size_t pl;
  uint8_t *qd;
  size_t ql;
  uint8_t *gd;
  size_t gl;
  uint8_t *yd;
  size_t yl;
  uint8_t *xd;
  size_t xl;
} bcrypto_dsa_key_t;

void
bcrypto_dsa_key_init(bcrypto_dsa_key_t *key);

void
bcrypto_dsa_key_free(bcrypto_dsa_key_t *key);

bcrypto_dsa_key_t *
bcrypto_dsa_generate_params(int bits);

bcrypto_dsa_key_t *
bcrypto_dsa_generate(bcrypto_dsa_key_t *params);

bool
bcrypto_dsa_create_pub(
  bcrypto_dsa_key_t *priv,
  uint8_t **out,
  size_t *out_len
);

bool
bcrypto_dsa_sign(
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_dsa_key_t *priv,
  uint8_t **r,
  size_t *r_len,
  uint8_t **s,
  size_t *s_len
);

bool
bcrypto_dsa_verify(
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *r,
  size_t r_len,
  const uint8_t *s,
  size_t s_len,
  const bcrypto_dsa_key_t *pub
);

#if defined(__cplusplus)
}
#endif

#endif
