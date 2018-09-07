#ifndef _BCRYPTO_RSA_H
#define _BCRYPTO_RSA_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct bcrypto_rsa_key_s {
  uint8_t *nd;
  size_t nl;
  uint8_t *ed;
  size_t el;
  uint8_t *dd;
  size_t dl;
  uint8_t *pd;
  size_t pl;
  uint8_t *qd;
  size_t ql;
  uint8_t *dpd;
  size_t dpl;
  uint8_t *dqd;
  size_t dql;
  uint8_t *qid;
  size_t qil;
} bcrypto_rsa_key_t;

void
bcrypto_rsa_key_init(bcrypto_rsa_key_t *key);

void
bcrypto_rsa_key_free(bcrypto_rsa_key_t *key);

bcrypto_rsa_key_t *
bcrypto_rsa_privkey_generate(int bits, unsigned long long exp);

bool
bcrypto_rsa_privkey_compute(
  const bcrypto_rsa_key_t *priv,
  bcrypto_rsa_key_t **key
);

bool
bcrypto_rsa_privkey_verify(const bcrypto_rsa_key_t *priv);

bool
bcrypto_rsa_privkey_export(
  const bcrypto_rsa_key_t *priv,
  uint8_t **out,
  size_t *out_len
);

bcrypto_rsa_key_t *
bcrypto_rsa_privkey_import(
  const uint8_t *raw,
  size_t raw_len
);

bool
bcrypto_rsa_pubkey_verify(const bcrypto_rsa_key_t *pub);

bool
bcrypto_rsa_pubkey_export(
  const bcrypto_rsa_key_t *pub,
  uint8_t **out,
  size_t *out_len
);

bcrypto_rsa_key_t *
bcrypto_rsa_pubkey_import(
  const uint8_t *raw,
  size_t raw_len
);

bool
bcrypto_rsa_sign(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  uint8_t **sig,
  size_t *sig_len
);

bool
bcrypto_rsa_verify(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *sig,
  size_t sig_len,
  const bcrypto_rsa_key_t *pub
);

bool
bcrypto_rsa_encrypt(
  int type,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *pub,
  uint8_t **ct,
  size_t *ct_len
);

bool
bcrypto_rsa_decrypt(
  int type,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  uint8_t **pt,
  size_t *pt_len
);

#if defined(__cplusplus)
}
#endif

#endif
