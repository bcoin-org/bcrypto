/*!
 * cipher.h - ciphers for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef _TORSION_CIPHER_H
#define _TORSION_CIPHER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * Symbol Aliases
 */

#define aes_init torsion_aes_init
#define aes_init_encrypt torsion_aes_init_encrypt
#define aes_init_decrypt torsion_aes_init_decrypt
#define aes_encrypt torsion_aes_encrypt
#define aes_decrypt torsion_aes_decrypt
#define blowfish_init torsion_blowfish_init
#define blowfish_stream2word torsion_blowfish_stream2word
#define blowfish_expand0state torsion_blowfish_expand0state
#define blowfish_expandstate torsion_blowfish_expandstate
#define blowfish_enc torsion_blowfish_enc
#define blowfish_dec torsion_blowfish_dec
#define blowfish_encrypt torsion_blowfish_encrypt
#define blowfish_decrypt torsion_blowfish_decrypt
#define camellia_init torsion_camellia_init
#define camellia_encrypt torsion_camellia_encrypt
#define camellia_decrypt torsion_camellia_decrypt
#define cast5_init torsion_cast5_init
#define cast5_encrypt torsion_cast5_encrypt
#define cast5_decrypt torsion_cast5_decrypt
#define des_init torsion_des_init
#define des_encrypt torsion_des_encrypt
#define des_decrypt torsion_des_decrypt
#define des_ede_init torsion_des_ede_init
#define des_ede_encrypt torsion_des_ede_encrypt
#define des_ede_decrypt torsion_des_ede_decrypt
#define des_ede3_init torsion_des_ede3_init
#define des_ede3_encrypt torsion_des_ede3_encrypt
#define des_ede3_decrypt torsion_des_ede3_decrypt
#define idea_init torsion_idea_init
#define idea_init_encrypt torsion_idea_init_encrypt
#define idea_init_decrypt torsion_idea_init_decrypt
#define idea_encrypt torsion_idea_encrypt
#define idea_decrypt torsion_idea_decrypt
#define rc2_init torsion_rc2_init
#define rc2_encrypt torsion_rc2_encrypt
#define rc2_decrypt torsion_rc2_decrypt
#define rc4_init torsion_rc4_init
#define rc4_encrypt torsion_rc4_encrypt
#define serpent_init torsion_serpent_init
#define serpent_encrypt torsion_serpent_encrypt
#define serpent_decrypt torsion_serpent_decrypt
#define twofish_init torsion_twofish_init
#define twofish_encrypt torsion_twofish_encrypt
#define twofish_decrypt torsion_twofish_decrypt
#define pkcs7_pad torsion_pkcs7_pad
#define pkcs7_unpad torsion_pkcs7_unpad
#define cipher_key_size torsion_cipher_key_size
#define cipher_block_size torsion_cipher_block_size
#define cipher_init torsion_cipher_init
#define cipher_encrypt torsion_cipher_encrypt
#define cipher_decrypt torsion_cipher_decrypt
#define ecb_init torsion_ecb_init
#define ecb_encrypt torsion_ecb_encrypt
#define ecb_decrypt torsion_ecb_decrypt
#define cbc_init torsion_cbc_init
#define cbc_encrypt torsion_cbc_encrypt
#define cbc_decrypt torsion_cbc_decrypt
#define ctr_init torsion_ctr_init
#define ctr_crypt torsion_ctr_crypt
#define cfb_init torsion_cfb_init
#define cfb_encrypt torsion_cfb_encrypt
#define cfb_decrypt torsion_cfb_decrypt
#define ofb_init torsion_ofb_init
#define ofb_crypt torsion_ofb_crypt
#define gcm_init torsion_gcm_init
#define gcm_aad torsion_gcm_aad
#define gcm_encrypt torsion_gcm_encrypt
#define gcm_decrypt torsion_gcm_decrypt
#define gcm_digest torsion_gcm_digest
#define cipher_mode_init torsion_cipher_mode_init
#define cipher_mode_aad torsion_cipher_mode_aad
#define cipher_mode_encrypt torsion_cipher_mode_encrypt
#define cipher_mode_decrypt torsion_cipher_mode_decrypt
#define cipher_mode_digest torsion_cipher_mode_digest
#define cipher_mode_verify torsion_cipher_mode_verify
#define cipher_stream_init torsion_cipher_stream_init
#define cipher_stream_set_aad torsion_cipher_stream_set_aad
#define cipher_stream_set_tag torsion_cipher_stream_set_tag
#define cipher_stream_get_tag torsion_cipher_stream_get_tag
#define cipher_stream_update torsion_cipher_stream_update
#define cipher_stream_update_size torsion_cipher_stream_update_size
#define cipher_stream_final torsion_cipher_stream_final
#define cipher_static_encrypt torsion_cipher_static_encrypt
#define cipher_static_decrypt torsion_cipher_static_decrypt

/*
 * Definitions
 */

#define CIPHER_AES128 0
#define CIPHER_AES192 1
#define CIPHER_AES256 2
#define CIPHER_BLOWFISH 3
#define CIPHER_CAMELLIA128 4
#define CIPHER_CAMELLIA192 5
#define CIPHER_CAMELLIA256 6
#define CIPHER_CAST5 7
#define CIPHER_DES 8
#define CIPHER_DES_EDE 9
#define CIPHER_DES_EDE3 10
#define CIPHER_IDEA 11
#define CIPHER_RC2 12
#define CIPHER_RC2_GUTMANN 13
#define CIPHER_RC2_40 14
#define CIPHER_RC2_64 15
#define CIPHER_RC2_128 16
#define CIPHER_RC2_128_GUTMANN 17
#define CIPHER_SERPENT128 18
#define CIPHER_SERPENT192 19
#define CIPHER_SERPENT256 20
#define CIPHER_TWOFISH128 21
#define CIPHER_TWOFISH192 22
#define CIPHER_TWOFISH256 23
#define CIPHER_MAX 23

#define CIPHER_MODE_RAW 0
#define CIPHER_MODE_ECB 1
#define CIPHER_MODE_CBC 2
#define CIPHER_MODE_CTR 3
#define CIPHER_MODE_CFB 4
#define CIPHER_MODE_OFB 5
#define CIPHER_MODE_GCM 6
#define CIPHER_MODE_MAX 6

#define CIPHER_MAX_BLOCK_SIZE 16
#define CIPHER_MAX_TAG_SIZE 16

#define _CIPHER_BLOCKS(n) \
  (((n) + CIPHER_MAX_BLOCK_SIZE - 1) / CIPHER_MAX_BLOCK_SIZE)

/* One extra block due to ctx->last. */
#define CIPHER_MAX_UPDATE_SIZE(n) \
  ((_CIPHER_BLOCKS(n) + 1) * CIPHER_MAX_BLOCK_SIZE)

#define CIPHER_MAX_ENCRYPT_SIZE(n) CIPHER_MAX_UPDATE_SIZE(n)
#define CIPHER_MAX_DECRYPT_SIZE(n) CIPHER_MAX_UPDATE_SIZE(n)

/*
 * Structs
 */

typedef struct _aes_s {
  unsigned int rounds;
  uint32_t enckey[60];
  uint32_t deckey[60];
} aes_t;

typedef struct _blowfish_s {
  uint32_t S[4][256];
  uint32_t P[18];
} blowfish_t;

typedef struct _camellia_s {
  unsigned int bits;
  uint32_t key[68];
} camellia_t;

typedef struct _cast5_s {
  uint32_t masking[16];
  uint8_t rotate[16];
} cast5_t;

typedef struct _des_s {
  uint32_t keys[32];
} des_t;

typedef struct _des_ede_s {
  des_t x;
  des_t y;
} des_ede_t;

typedef struct _des_ede3_s {
  des_t x;
  des_t y;
  des_t z;
} des_ede3_t;

typedef struct _idea_s {
  uint16_t enckey[52];
  uint16_t deckey[52];
} idea_t;

typedef struct _rc2_s {
  uint16_t k[64];
} rc2_t;

typedef struct _rc4_s {
  uint8_t s[256];
  uint8_t i;
  uint8_t j;
} rc4_t;

typedef struct _serpent_s {
  uint32_t subkeys[132];
} serpent_t;

typedef struct _twofish_s {
  uint32_t S[4][256];
  uint32_t k[40];
} twofish_t;

typedef struct _cipher_s {
  int type;
  union {
    aes_t aes;
    blowfish_t blowfish;
    camellia_t camellia;
    cast5_t cast5;
    des_t des;
    des_ede_t ede;
    des_ede3_t ede3;
    idea_t idea;
    rc2_t rc2;
    serpent_t serpent;
    twofish_t twofish;
  } ctx;
} cipher_t;

typedef struct _ecb_s {
  size_t size;
} ecb_t;

typedef struct _cbc_s {
  unsigned char prev[CIPHER_MAX_BLOCK_SIZE];
  size_t size;
} cbc_t;

typedef struct _ctr_s {
  uint8_t ctr[CIPHER_MAX_BLOCK_SIZE];
  unsigned char state[CIPHER_MAX_BLOCK_SIZE];
  size_t size;
  size_t pos;
} ctr_t;

typedef struct _cfb_s {
  unsigned char state[CIPHER_MAX_BLOCK_SIZE];
  unsigned char prev[CIPHER_MAX_BLOCK_SIZE];
  size_t size;
  size_t pos;
} cfb_t;

typedef struct _ofb_s {
  unsigned char state[CIPHER_MAX_BLOCK_SIZE];
  size_t size;
  size_t pos;
} ofb_t;

struct __ghash_fe_s {
  uint64_t lo;
  uint64_t hi;
};

struct __ghash_s {
  struct __ghash_fe_s state;
  struct __ghash_fe_s table[16];
  unsigned char block[16];
  uint64_t adlen;
  uint64_t ctlen;
  size_t size;
};

typedef struct _gcm_s {
  struct __ghash_s hash;
  uint8_t ctr[16];
  unsigned char state[16];
  unsigned char mask[16];
  size_t pos;
} gcm_t;

typedef struct _cipher_mode_s {
  int type;
  union {
    ecb_t ecb;
    cbc_t cbc;
    ctr_t ctr;
    cfb_t cfb;
    ofb_t ofb;
    gcm_t gcm;
  } mode;
} cipher_mode_t;

typedef struct _cipher_stream_s {
  int encrypt;
  int padding;
  size_t block_size;
  size_t block_pos;
  size_t last_size;
  size_t tag_len;
  unsigned char block[CIPHER_MAX_BLOCK_SIZE];
  unsigned char last[CIPHER_MAX_BLOCK_SIZE];
  unsigned char tag[CIPHER_MAX_TAG_SIZE];
  cipher_t cipher;
  cipher_mode_t mode;
} cipher_stream_t;

/*
 * AES
 */

void
aes_init(aes_t *ctx, unsigned int bits, const unsigned char *key);

void
aes_init_encrypt(aes_t *ctx, unsigned int bits, const unsigned char *key);

void
aes_init_decrypt(aes_t *ctx);

void
aes_encrypt(const aes_t *ctx, unsigned char *dst, const unsigned char *src);

void
aes_decrypt(const aes_t *ctx, unsigned char *dst, const unsigned char *src);

/*
 * Blowfish
 */

void
blowfish_init(blowfish_t *ctx,
              const unsigned char *key, size_t key_len,
              const unsigned char *salt, size_t salt_len);

uint32_t
blowfish_stream2word(const unsigned char *data, size_t len, size_t *off);

void
blowfish_expand0state(blowfish_t *ctx,
                      const unsigned char *key,
                      size_t key_len);

void
blowfish_expandstate(blowfish_t *ctx,
                     const unsigned char *key, size_t key_len,
                     const unsigned char *data, size_t data_len);

void
blowfish_enc(const blowfish_t *ctx, uint32_t *data, size_t len);

void
blowfish_dec(const blowfish_t *ctx, uint32_t *data, size_t len);

void
blowfish_encrypt(const blowfish_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src);

void
blowfish_decrypt(const blowfish_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src);

/*
 * Camellia
 */

void
camellia_init(camellia_t *ctx, unsigned int bits, const unsigned char *key);

void
camellia_encrypt(const camellia_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src);

void
camellia_decrypt(const camellia_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src);

/*
 * CAST5
 */

void
cast5_init(cast5_t *ctx, const unsigned char *key);

void
cast5_encrypt(const cast5_t *ctx,
              unsigned char *dst,
              const unsigned char *src);

void
cast5_decrypt(const cast5_t *ctx,
              unsigned char *dst,
              const unsigned char *src);

/*
 * DES
 */

void
des_init(des_t *ctx, const unsigned char *key);

void
des_encrypt(const des_t *ctx, unsigned char *dst, const unsigned char *src);

void
des_decrypt(const des_t *ctx, unsigned char *dst, const unsigned char *src);

/*
 * DES-EDE
 */

void
des_ede_init(des_ede_t *ctx, const unsigned char *key);

void
des_ede_encrypt(const des_ede_t *ctx,
                unsigned char *dst,
                const unsigned char *src);

void
des_ede_decrypt(const des_ede_t *ctx,
                unsigned char *dst,
                const unsigned char *src);

/*
 * DES-EDE3
 */

void
des_ede3_init(des_ede3_t *ctx, const unsigned char *key);

void
des_ede3_encrypt(const des_ede3_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src);

void
des_ede3_decrypt(const des_ede3_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src);

/*
 * IDEA
 */

void
idea_init(idea_t *ctx, const unsigned char *key);

void
idea_init_encrypt(idea_t *ctx, const unsigned char *key);

void
idea_init_decrypt(idea_t *ctx);

void
idea_encrypt(const idea_t *ctx, unsigned char *dst, const unsigned char *src);

void
idea_decrypt(const idea_t *ctx, unsigned char *dst, const unsigned char *src);

/*
 * RC2
 */

void
rc2_init(rc2_t *ctx,
         const unsigned char *key,
         size_t key_len,
         unsigned int ekb);

void
rc2_encrypt(const rc2_t *ctx, unsigned char *dst, const unsigned char *src);

void
rc2_decrypt(const rc2_t *ctx, unsigned char *dst, const unsigned char *src);

/*
 * RC4
 */

void
rc4_init(rc4_t *ctx, const unsigned char *key, size_t key_len);

void
rc4_encrypt(rc4_t *ctx,
            unsigned char *dst,
            const unsigned char *src,
            size_t len);

/*
 * Serpent
 */

void
serpent_init(serpent_t *ctx, unsigned int bits, const unsigned char *key);

void
serpent_encrypt(const serpent_t *ctx,
                unsigned char *dst,
                const unsigned char *src);

void
serpent_decrypt(const serpent_t *ctx,
                unsigned char *dst,
                const unsigned char *src);

/*
 * Twofish
 */

void
twofish_init(twofish_t *ctx, unsigned int bits, const unsigned char *key);

void
twofish_encrypt(const twofish_t *ctx,
                unsigned char *dst,
                const unsigned char *src);

void
twofish_decrypt(const twofish_t *ctx,
                unsigned char *dst,
                const unsigned char *src);

/*
 * PKCS7
 */

void
pkcs7_pad(unsigned char *dst,
          const unsigned char *src,
          size_t len,
          size_t size);

int
pkcs7_unpad(unsigned char *dst,
            size_t *len,
            const unsigned char *src,
            size_t size);

/*
 * Cipher
 */

size_t
cipher_key_size(int type);

size_t
cipher_block_size(int type);

int
cipher_init(cipher_t *ctx, int type, const unsigned char *key, size_t key_len);

void
cipher_encrypt(const cipher_t *ctx,
               unsigned char *dst,
               const unsigned char *src);

void
cipher_decrypt(const cipher_t *ctx,
               unsigned char *dst,
               const unsigned char *src);

/*
 * ECB
 */

int
ecb_init(ecb_t *mode, const cipher_t *cipher);

void
ecb_encrypt(ecb_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

void
ecb_decrypt(ecb_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

/*
 * CBC
 */

int
cbc_init(cbc_t *mode, const cipher_t *cipher,
         const unsigned char *iv, size_t iv_len);

void
cbc_encrypt(cbc_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

void
cbc_decrypt(cbc_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

/*
 * CTR
 */

int
ctr_init(ctr_t *mode, const cipher_t *cipher,
         const unsigned char *iv, size_t iv_len);

void
ctr_crypt(ctr_t *mode, const cipher_t *cipher,
          unsigned char *dst, const unsigned char *src, size_t len);

/*
 * CFB
 */

int
cfb_init(cfb_t *mode, const cipher_t *cipher,
         const unsigned char *iv, size_t iv_len);

void
cfb_encrypt(cfb_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

void
cfb_decrypt(cfb_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

/*
 * OFB
 */

int
ofb_init(ofb_t *mode, const cipher_t *cipher,
         const unsigned char *iv, size_t iv_len);

void
ofb_crypt(ofb_t *mode, const cipher_t *cipher,
          unsigned char *dst, const unsigned char *src, size_t len);

/*
 * GCM
 */

int
gcm_init(gcm_t *mode, const cipher_t *cipher,
         const unsigned char *iv, size_t iv_len);

void
gcm_aad(gcm_t *mode, const unsigned char *aad, size_t len);

void
gcm_encrypt(gcm_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

void
gcm_decrypt(gcm_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

void
gcm_digest(gcm_t *mode, unsigned char *mac);

/*
 * Cipher Mode
 */

int
cipher_mode_init(cipher_mode_t *ctx, const cipher_t *cipher,
                 int type, const unsigned char *iv, size_t iv_len);

void
cipher_mode_aad(cipher_mode_t *ctx, const unsigned char *aad, size_t len);

void
cipher_mode_encrypt(cipher_mode_t *ctx,
                    const cipher_t *cipher,
                    unsigned char *dst,
                    const unsigned char *src,
                    size_t len);

void
cipher_mode_decrypt(cipher_mode_t *ctx,
                    const cipher_t *cipher,
                    unsigned char *dst,
                    const unsigned char *src,
                    size_t len);

void
cipher_mode_digest(cipher_mode_t *ctx, unsigned char *mac);

int
cipher_mode_verify(cipher_mode_t *ctx,
                   const unsigned char *tag,
                   size_t tag_len);

/*
 * Cipher Stream
 */

int
cipher_stream_init(cipher_stream_t *ctx,
                   int type, int mode, int encrypt,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *iv, size_t iv_len);

int
cipher_stream_set_aad(cipher_stream_t *ctx,
                      const unsigned char *aad,
                      size_t len);

int
cipher_stream_set_tag(cipher_stream_t *ctx,
                      const unsigned char *tag,
                      size_t len);

int
cipher_stream_get_tag(cipher_stream_t *ctx, unsigned char *tag, size_t *len);

void
cipher_stream_update(cipher_stream_t *ctx,
                     unsigned char *output, size_t *output_len,
                     const unsigned char *input, size_t input_len);

size_t
cipher_stream_update_size(const cipher_stream_t *ctx, size_t input_len);

int
cipher_stream_final(cipher_stream_t *ctx,
                    unsigned char *output,
                    size_t *output_len);

/*
 * Static Encryption/Decryption
 */

int
cipher_static_encrypt(unsigned char *ct,
                      size_t *ct_len,
                      int type,
                      int mode,
                      const unsigned char *key,
                      size_t key_len,
                      const unsigned char *iv,
                      size_t iv_len,
                      const unsigned char *pt,
                      size_t pt_len);

int
cipher_static_decrypt(unsigned char *pt,
                      size_t *pt_len,
                      int type,
                      int mode,
                      const unsigned char *key,
                      size_t key_len,
                      const unsigned char *iv,
                      size_t iv_len,
                      const unsigned char *ct,
                      size_t ct_len);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_CIPHER_H */
