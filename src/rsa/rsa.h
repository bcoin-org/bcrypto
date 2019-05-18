#ifndef _BCRYPTO_RSA_H
#define _BCRYPTO_RSA_H

#include <stdlib.h>
#include <stdint.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define BCRYPTO_RSA_DEFAULT_BITS 2048
#define BCRYPTO_RSA_DEFAULT_EXP 65537
#define BCRYPTO_RSA_MIN_BITS 512
#define BCRYPTO_RSA_MAX_BITS 16384
#define BCRYPTO_RSA_MIN_BYTES ((BCRYPTO_RSA_MIN_BITS + 7) / 8)
#define BCRYPTO_RSA_MAX_BYTES ((BCRYPTO_RSA_MAX_BITS + 7) / 8)
#define BCRYPTO_RSA_MIN_EXP 3ull
#define BCRYPTO_RSA_MAX_EXP 0x1ffffffffull
#define BCRYPTO_RSA_MIN_EXP_BITS 2
#define BCRYPTO_RSA_MAX_EXP_BITS 33
#define BCRYPTO_RSA_MAX_PREFIX 0x15

#ifdef BCRYPTO_WASM
typedef uint8_t bcrypto_rsa_key_t;
#else
typedef struct bcrypto_rsa_key_s {
  uint8_t *slab;
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
bcrypto_rsa_key_uninit(bcrypto_rsa_key_t *key);

size_t
bcrypto_rsa_key_size(const bcrypto_rsa_key_t *key);
#endif

int
bcrypto_rsa_privkey_generate(bcrypto_rsa_key_t *out, int bits,
                             uint64_t exponent);

int
bcrypto_rsa_privkey_compute(bcrypto_rsa_key_t *out,
                            const bcrypto_rsa_key_t *key);

int
bcrypto_rsa_privkey_verify(const bcrypto_rsa_key_t *key);

int
bcrypto_rsa_pubkey_verify(const bcrypto_rsa_key_t *key);

int
bcrypto_rsa_sign(uint8_t *out,
                 int type,
                 const uint8_t *msg,
                 size_t msg_len,
                 const bcrypto_rsa_key_t *key);

int
bcrypto_rsa_verify(int type,
                   const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *sig,
                   size_t sig_len,
                   const bcrypto_rsa_key_t *key);

int
bcrypto_rsa_encrypt(uint8_t *out,
                    const uint8_t *pt,
                    size_t pt_len,
                    const bcrypto_rsa_key_t *key);

int
bcrypto_rsa_decrypt(uint8_t *out,
                    size_t *out_len,
                    const uint8_t *ct,
                    size_t ct_len,
                    const bcrypto_rsa_key_t *key);

int
bcrypto_rsa_encrypt_oaep(uint8_t *out,
                         int type,
                         const uint8_t *pt,
                         size_t pt_len,
                         const bcrypto_rsa_key_t *key,
                         const uint8_t *label,
                         size_t label_len);

int
bcrypto_rsa_decrypt_oaep(uint8_t *out,
                         size_t *out_len,
                         int type,
                         const uint8_t *ct,
                         size_t ct_len,
                         const bcrypto_rsa_key_t *key,
                         const uint8_t *label,
                         size_t label_len);

int
bcrypto_rsa_sign_pss(uint8_t *out,
                     int type,
                     const uint8_t *msg,
                     size_t msg_len,
                     const bcrypto_rsa_key_t *key,
                     int salt_len);

int
bcrypto_rsa_verify_pss(int type,
                       const uint8_t *msg,
                       size_t msg_len,
                       const uint8_t *sig,
                       size_t sig_len,
                       const bcrypto_rsa_key_t *key,
                       int salt_len);

int
bcrypto_rsa_encrypt_raw(uint8_t *out,
                        const uint8_t *pt,
                        size_t pt_len,
                        const bcrypto_rsa_key_t *key);

int
bcrypto_rsa_decrypt_raw(uint8_t *out,
                        const uint8_t *ct,
                        size_t ct_len,
                        const bcrypto_rsa_key_t *key);

int
bcrypto_rsa_veil(uint8_t *out,
                 const uint8_t *ct,
                 size_t ct_len,
                 size_t bits,
                 const bcrypto_rsa_key_t *key);

int
bcrypto_rsa_unveil(uint8_t *out,
                   const uint8_t *veiled,
                   size_t veiled_len,
                   size_t bits,
                   const bcrypto_rsa_key_t *key);

int
bcrypto_rsa_has_hash(int type);

#if defined(__cplusplus)
}
#endif

#endif
