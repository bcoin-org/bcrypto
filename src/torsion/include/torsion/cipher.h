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
#define idea_init_encrypt torsion_idea_init_encrypt
#define idea_init_decrypt torsion_idea_init_decrypt
#define idea_encrypt torsion_idea_encrypt
#define idea_decrypt torsion_idea_decrypt
#define rc2_init torsion_rc2_init
#define rc2_encrypt torsion_rc2_encrypt
#define rc2_decrypt torsion_rc2_decrypt
#define twofish_init torsion_twofish_init
#define twofish_encrypt torsion_twofish_encrypt
#define twofish_decrypt torsion_twofish_decrypt
#define ghash_init torsion_ghash_init
#define ghash_aad torsion_ghash_aad
#define ghash_update torsion_ghash_update
#define ghash_final torsion_ghash_final
#define cipher_init torsion_cipher_init
#define cipher_set_aad torsion_cipher_set_aad
#define cipher_set_tag torsion_cipher_set_tag
#define cipher_get_tag torsion_cipher_get_tag
#define cipher_update torsion_cipher_update
#define cipher_update_size torsion_cipher_update_size
#define cipher_final torsion_cipher_final
#define cipher_encrypt torsion_cipher_encrypt
#define cipher_decrypt torsion_cipher_decrypt

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
#define CIPHER_TWOFISH128 13
#define CIPHER_TWOFISH192 14
#define CIPHER_TWOFISH256 15
#define CIPHER_MAX 15

#define CIPHER_MODE_ECB 0
#define CIPHER_MODE_CBC 1
#define CIPHER_MODE_CTR 2
#define CIPHER_MODE_CFB 3
#define CIPHER_MODE_OFB 4
#define CIPHER_MODE_GCM 5
#define CIPHER_MODE_MAX 5

#define CIPHER_MAX_BLOCK_SIZE 16

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
  uint32_t key[60];
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
  uint16_t ek[52];
  uint16_t dk[52];
} idea_t;

typedef struct _rc2_s {
  uint16_t k[64];
} rc2_t;

typedef struct _twofish_s {
  uint32_t S[4][256];
  uint32_t k[40];
} twofish_t;

struct ghash_fe_s {
  uint64_t lo;
  uint64_t hi;
};

typedef struct _ghash_s {
  struct ghash_fe_s state;
  uint8_t block[16];
  size_t size;
  uint64_t adlen;
  uint64_t ctlen;
  struct ghash_fe_s table[16];
} ghash_t;

typedef struct _cipher_s {
  int type;
  int mode;
  int encrypt;
  size_t block_size;
  size_t block_pos;
  size_t last_size;
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
    twofish_t twofish;
  } ctx;
  unsigned char block[CIPHER_MAX_BLOCK_SIZE];
  unsigned char last[CIPHER_MAX_BLOCK_SIZE];
  unsigned char prev[CIPHER_MAX_BLOCK_SIZE];
  unsigned char state[CIPHER_MAX_BLOCK_SIZE];
  unsigned char ctr[CIPHER_MAX_BLOCK_SIZE];
  ghash_t ghash;
  unsigned char mask[16];
  unsigned char tag[16];
  size_t tag_len;
  size_t ctr_pos;
} cipher_t;

/*
 * AES
 */

void
aes_init_encrypt(aes_t *ctx, unsigned int bits, const unsigned char *key);

void
aes_init_decrypt(aes_t *ctx, unsigned int bits, const unsigned char *key);

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
blowfish_enc(blowfish_t *ctx, uint32_t *data, size_t len);

void
blowfish_dec(blowfish_t *ctx, uint32_t *data, size_t len);

void
blowfish_encrypt(blowfish_t *ctx, unsigned char *dst, const unsigned char *src);

void
blowfish_decrypt(blowfish_t *ctx, unsigned char *dst, const unsigned char *src);

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
idea_init_encrypt(idea_t *ctx, const unsigned char *key);

void
idea_init_decrypt(idea_t *ctx, const unsigned char *key);

void
idea_encrypt(const idea_t *ctx, unsigned char *dst, const unsigned char *src);

void
idea_decrypt(const idea_t *ctx, unsigned char *dst, const unsigned char *src);

/*
 * RC2
 */

void
rc2_init(rc2_t *ctx, const unsigned char *key, size_t key_len);

void
rc2_encrypt(const rc2_t *ctx, unsigned char *dst, const unsigned char *src);

void
rc2_decrypt(const rc2_t *ctx, unsigned char *dst, const unsigned char *src);

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
 * GHASH
 */

void
ghash_init(ghash_t *ctx, const unsigned char *key);

void
ghash_aad(ghash_t *ctx, const unsigned char *data, size_t len);

void
ghash_update(ghash_t *ctx, const unsigned char *data, size_t len);

void
ghash_final(ghash_t *ctx, unsigned char *out);

/*
 * Cipher
 */

int
cipher_init(cipher_t *ctx, int type, int mode, int encrypt,
            const unsigned char *key, size_t key_len,
            const unsigned char *iv, size_t iv_len);

int
cipher_set_aad(cipher_t *ctx, const unsigned char *aad, size_t len);

int
cipher_set_tag(cipher_t *ctx, const unsigned char *tag, size_t len);

int
cipher_get_tag(cipher_t *ctx, unsigned char *tag, size_t *len);

void
cipher_update(cipher_t *ctx,
              unsigned char *output, size_t *output_len,
              const unsigned char *input, size_t input_len);

size_t
cipher_update_size(const cipher_t *ctx, size_t input_len);

int
cipher_final(cipher_t *ctx, unsigned char *output, size_t *output_len);

int
cipher_encrypt(unsigned char *ct,
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
cipher_decrypt(unsigned char *pt,
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
