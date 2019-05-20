#ifndef _BCRYPTO_DSA_H
#define _BCRYPTO_DSA_H

#include <stdlib.h>
#include <stdint.h>
#include "../nettle/dsa.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define BCRYPTO_DSA_DEFAULT_BITS 2048
#define BCRYPTO_DSA_MIN_BITS 512
#define BCRYPTO_DSA_MAX_BITS 10000
#define BCRYPTO_DSA_MIN_FIELD_SIZE (BCRYPTO_DSA_MIN_BITS / 8)
#define BCRYPTO_DSA_MAX_FIELD_SIZE (BCRYPTO_DSA_MAX_BITS / 8)
#define BCRYPTO_DSA_MIN_SCALAR_SIZE 20
#define BCRYPTO_DSA_MAX_SCALAR_SIZE 32
#define BCRYPTO_DSA_MAX_SIG_SIZE (BCRYPTO_DSA_MAX_SCALAR_SIZE * 2)
#define BCRYPTO_DSA_MAX_DER_SIZE (9 + BCRYPTO_DSA_MAX_SIG_SIZE)

#ifdef BCRYPTO_WASM
typedef uint8_t bcrypto_dsa_key_t;
#else
typedef struct bcrypto_dsa_key_s {
  uint8_t *slab;
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
#endif

void
bcrypto_dsa_key_init(bcrypto_dsa_key_t *key);

void
bcrypto_dsa_key_uninit(bcrypto_dsa_key_t *key);

size_t
bcrypto_dsa_key_psize(const bcrypto_dsa_key_t *key);

size_t
bcrypto_dsa_key_qsize(const bcrypto_dsa_key_t *key);

size_t
bcrypto_dsa_sig_size(const bcrypto_dsa_key_t *key);

size_t
bcrypto_dsa_der_size(const bcrypto_dsa_key_t *key);

void
bcrypto_dsa_rs2sig(struct dsa_signature *out,
                   const uint8_t *sig, size_t qsize);

void
bcrypto_dsa_sig2rs(uint8_t *out,
                   const struct dsa_signature *sig,
                   size_t qsize);

int
bcrypto_dsa_der2sig(struct dsa_signature *out,
                    const uint8_t *raw, size_t raw_len,
                    size_t qsize);

int
bcrypto_dsa_sig2der(uint8_t *out,
                    size_t *out_len,
                    const struct dsa_signature *sig,
                    size_t qsize);

int
bcrypto_dsa_params_generate(bcrypto_dsa_key_t *out, int bits);

int
bcrypto_dsa_params_verify(const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_params_export(uint8_t *out,
                          size_t *out_len,
                          const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_params_import(bcrypto_dsa_key_t *out,
                          const uint8_t *raw, size_t raw_len);

int
bcrypto_dsa_privkey_create(bcrypto_dsa_key_t *out,
                           const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_privkey_compute(uint8_t *out,
                            size_t *out_len,
                            const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_privkey_verify(const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_privkey_export(uint8_t *out,
                           size_t *out_len,
                           const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_privkey_import(bcrypto_dsa_key_t *out,
                           const uint8_t *raw, size_t raw_len);

int
bcrypto_dsa_privkey_export_pkcs8(uint8_t *out,
                                 size_t *out_len,
                                 const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_privkey_import_pkcs8(bcrypto_dsa_key_t *key,
                                 const uint8_t *raw, size_t raw_len);

int
bcrypto_dsa_pubkey_verify(const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_pubkey_export(uint8_t *out,
                          size_t *out_len,
                          const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_pubkey_import(bcrypto_dsa_key_t *out,
                          const uint8_t *raw, size_t raw_len);

int
bcrypto_dsa_pubkey_export_spki(uint8_t *out,
                               size_t *out_len,
                               const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_pubkey_import_spki(bcrypto_dsa_key_t *out,
                               const uint8_t *raw, size_t raw_len);

int
bcrypto_dsa_sig_export(uint8_t *out,
                       size_t *out_len,
                       const uint8_t *sig,
                       size_t sig_len,
                       size_t size);

int
bcrypto_dsa_sig_import(uint8_t *out,
                       const uint8_t *sig,
                       size_t sig_len,
                       size_t size);

int
bcrypto_dsa_sign(uint8_t *out,
                 const uint8_t *msg,
                 size_t msg_len,
                 const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_sign_der(uint8_t *out,
                     size_t *out_len,
                     const uint8_t *msg,
                     size_t msg_len,
                     const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_verify(const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *sig,
                   size_t sig_len,
                   const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_verify_der(const uint8_t *msg,
                       size_t msg_len,
                       const uint8_t *sig,
                       size_t sig_len,
                       const bcrypto_dsa_key_t *key);

int
bcrypto_dsa_derive(uint8_t *out,
                   size_t *out_len,
                   const bcrypto_dsa_key_t *key_pub,
                   const bcrypto_dsa_key_t *key_prv);

#if defined(__cplusplus)
}
#endif

#endif
