/*!
 * kdf.h - kdf for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef _TORSION_KDF_H
#define _TORSION_KDF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * Symbol Aliases
 */

#define eb2k_derive torsion_eb2k_derive
#define hkdf_extract torsion_hkdf_extract
#define hkdf_expand torsion_hkdf_expand
#define pbkdf2_derive torsion_pbkdf2_derive
#define scrypt_derive torsion_scrypt_derive

/*
 * EB2K (OpenSSL Legacy)
 */

int
eb2k_derive(unsigned char *key,
            unsigned char *iv,
            int type,
            const unsigned char *passwd,
            size_t passwd_len,
            const unsigned char *salt,
            size_t salt_len,
            size_t key_len,
            size_t iv_len);

/*
 * HKDF
 */

int
hkdf_extract(unsigned char *out, int type,
             const unsigned char *ikm, size_t ikm_len,
             const unsigned char *salt, size_t salt_len);

int
hkdf_expand(unsigned char *out,
            int type,
            const unsigned char *prk,
            const unsigned char *info,
            size_t info_len,
            size_t len);

/*
 * PBKDF2
 */

int
pbkdf2_derive(unsigned char *out,
              int type,
              const unsigned char *pass,
              size_t pass_len,
              const unsigned char *salt,
              size_t salt_len,
              uint32_t iter,
              size_t len);

/*
 * Scrypt
 */

int
scrypt_derive(unsigned char *out,
              const unsigned char *pass,
              size_t pass_len,
              const unsigned char *salt,
              size_t salt_len,
              uint64_t N,
              uint32_t r,
              uint32_t p,
              size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_KDF_H */
