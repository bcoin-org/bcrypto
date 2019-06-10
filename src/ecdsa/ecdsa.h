#ifndef _BCRYPTO_ECDSA_H
#define _BCRYPTO_ECDSA_H

#include <stdint.h>
#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define BCRYPTO_HAS_ECDSA
#define BCRYPTO_ECDSA_MAX_FIELD_SIZE 66
#define BCRYPTO_ECDSA_MAX_SCALAR_SIZE 66
#define BCRYPTO_ECDSA_MAX_PUB_SIZE (1 + BCRYPTO_ECDSA_MAX_FIELD_SIZE * 2)
#define BCRYPTO_ECDSA_MAX_SIG_SIZE \
  (BCRYPTO_ECDSA_MAX_FIELD_SIZE + BCRYPTO_ECDSA_MAX_SCALAR_SIZE)
#define BCRYPTO_ECDSA_MAX_DER_SIZE (9 + BCRYPTO_ECDSA_MAX_SIG_SIZE)

#define BCRYPTO_CURVE_P192 1
#define BCRYPTO_CURVE_P224 2
#define BCRYPTO_CURVE_P256 3
#define BCRYPTO_CURVE_P384 4
#define BCRYPTO_CURVE_P521 5
#define BCRYPTO_CURVE_MIN 1
#define BCRYPTO_CURVE_MAX 5

size_t
bcrypto_ecdsa_field_bits(int type);

size_t
bcrypto_ecdsa_field_length(int type);

size_t
bcrypto_ecdsa_scalar_length(int type);

size_t
bcrypto_ecdsa_sig_length(int type);

int
bcrypto_ecdsa_privkey_generate(int type, uint8_t *out);

int
bcrypto_ecdsa_privkey_verify(int type, const uint8_t *key);

int
bcrypto_ecdsa_privkey_export(int type,
                             uint8_t *out,
                             size_t *out_len,
                             const uint8_t *key,
                             int compress);

int
bcrypto_ecdsa_privkey_import(int type,
                             uint8_t *out,
                             const uint8_t *raw,
                             size_t raw_len);

int
bcrypto_ecdsa_privkey_export_pkcs8(int type,
                                   uint8_t *out,
                                   size_t *out_len,
                                   const uint8_t *key,
                                   int compress);

int
bcrypto_ecdsa_privkey_import_pkcs8(int type,
                                   uint8_t *out,
                                   const uint8_t *raw,
                                   size_t raw_len);

int
bcrypto_ecdsa_privkey_tweak_add(int type,
                                uint8_t *out,
                                const uint8_t *key,
                                const uint8_t *tweak);

int
bcrypto_ecdsa_privkey_tweak_mul(int type,
                                uint8_t *out,
                                const uint8_t *key,
                                const uint8_t *tweak);

int
bcrypto_ecdsa_privkey_reduce(int type,
                             uint8_t *out,
                             const uint8_t *key,
                             size_t key_len);

int
bcrypto_ecdsa_privkey_negate(int type, uint8_t *out, const uint8_t *key);

int
bcrypto_ecdsa_privkey_invert(int type, uint8_t *out, const uint8_t *key);

int
bcrypto_ecdsa_pubkey_create(int type,
                            uint8_t *out,
                            size_t *out_len,
                            const uint8_t *key,
                            int compress);

int
bcrypto_ecdsa_pubkey_convert(int type,
                             uint8_t *out,
                             size_t *out_len,
                             const uint8_t *key,
                             size_t key_len,
                             int compress);

int
bcrypto_ecdsa_pubkey_verify(int type, const uint8_t *key, size_t key_len);

int
bcrypto_ecdsa_pubkey_export_spki(int type,
                                 uint8_t *out,
                                 size_t *out_len,
                                 const uint8_t *key,
                                 size_t key_len,
                                 int compress);

int
bcrypto_ecdsa_pubkey_import_spki(int type,
                                 uint8_t *out,
                                 const uint8_t *raw,
                                 size_t raw_len);

int
bcrypto_ecdsa_pubkey_tweak_add(int type,
                               uint8_t *out,
                               size_t *out_len,
                               const uint8_t *key,
                               size_t key_len,
                               const uint8_t *tweak,
                               int compress);

int
bcrypto_ecdsa_pubkey_tweak_mul(int type,
                               uint8_t *out,
                               size_t *out_len,
                               const uint8_t *key,
                               size_t key_len,
                               const uint8_t *tweak,
                               int compress);

int
bcrypto_ecdsa_pubkey_add(int type,
                         uint8_t *out,
                         size_t *out_len,
                         const uint8_t *key1,
                         size_t key1_len,
                         const uint8_t *key2,
                         size_t key2_len,
                         int compress);

int
bcrypto_ecdsa_pubkey_combine(int type,
                             uint8_t *out,
                             size_t *out_len,
                             const uint8_t **keys,
                             size_t *key_lens,
                             size_t length,
                             int compress);

int
bcrypto_ecdsa_pubkey_negate(int type,
                            uint8_t *out,
                            size_t *out_len,
                            const uint8_t *key,
                            size_t key_len,
                            int compress);

int
bcrypto_ecdsa_sig_normalize(int type,
                            uint8_t *out,
                            const uint8_t *sig);

int
bcrypto_ecdsa_sig_normalize_der(int type,
                                uint8_t *out,
                                size_t *out_len,
                                const uint8_t *sig,
                                size_t sig_len);

int
bcrypto_ecdsa_sig_export(int type,
                         uint8_t *out,
                         size_t *out_len,
                         const uint8_t *sig);

int
bcrypto_ecdsa_sig_import(int type,
                         uint8_t *out,
                         const uint8_t *sig,
                         size_t sig_len);

int
bcrypto_ecdsa_sig_low_s(int type, const uint8_t *sig);

int
bcrypto_ecdsa_sig_low_der(int type, const uint8_t *sig, size_t sig_len);

int
bcrypto_ecdsa_sign(int type,
                   uint8_t *out,
                   const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *key);

int
bcrypto_ecdsa_sign_der(int type,
                       uint8_t *out,
                       size_t *out_len,
                       const uint8_t *msg,
                       size_t msg_len,
                       const uint8_t *key);

int
bcrypto_ecdsa_sign_recoverable(int type,
                               uint8_t *out,
                               int *param,
                               const uint8_t *msg,
                               size_t msg_len,
                               const uint8_t *key);

int
bcrypto_ecdsa_sign_recoverable_der(int type,
                                   uint8_t *out,
                                   size_t *out_len,
                                   int *param,
                                   const uint8_t *msg,
                                   size_t msg_len,
                                   const uint8_t *key);

int
bcrypto_ecdsa_verify(int type,
                     const uint8_t *msg,
                     size_t msg_len,
                     const uint8_t *sig,
                     const uint8_t *key,
                     size_t key_len);

int
bcrypto_ecdsa_verify_der(int type,
                         const uint8_t *msg,
                         size_t msg_len,
                         const uint8_t *sig,
                         size_t sig_len,
                         const uint8_t *key,
                         size_t key_len);

int
bcrypto_ecdsa_recover(int type,
                      uint8_t *out,
                      size_t *out_len,
                      const uint8_t *msg,
                      size_t msg_len,
                      const uint8_t *sig,
                      int param,
                      int compress);

int
bcrypto_ecdsa_recover_der(int type,
                          uint8_t *out,
                          size_t *out_len,
                          const uint8_t *msg,
                          size_t msg_len,
                          const uint8_t *sig,
                          size_t sig_len,
                          int param,
                          int compress);

int
bcrypto_ecdsa_derive(int type,
                     uint8_t *out,
                     size_t *out_len,
                     const uint8_t *pub,
                     size_t pub_len,
                     const uint8_t *key,
                     int compress);

int
bcrypto_schnorr_sign(int type,
                     uint8_t *out,
                     const uint8_t *msg,
                     const uint8_t *key);

int
bcrypto_schnorr_verify(int type,
                       const uint8_t *msg,
                       const uint8_t *sig,
                       const uint8_t *key,
                       size_t key_len);

int
bcrypto_schnorr_batch_verify(int type,
                             const uint8_t **msgs,
                             const uint8_t **sigs,
                             const uint8_t **keys,
                             size_t *key_lens,
                             size_t length);

#if defined(__cplusplus)
}
#endif

#endif
