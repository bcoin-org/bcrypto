/*!
 * kdf.c - kdf for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on Tarsnap/scrypt:
 *   Copyright (c) 2005-2016, Colin Percival. All rights reserved.
 *   Copyright (c) 2005-2016, Tarsnap Backup Inc. All rights reserved.
 *   Copyright (c) 2014, Sean Kelly. All rights reserved.
 *   https://github.com/Tarsnap/scrypt
 *
 * EB2K Resources:
 *   https://github.com/openssl/openssl/blob/2e9d61e/crypto/evp/evp_key.c
 *
 * HKDF Resources:
 *   https://en.wikipedia.org/wiki/HKDF
 *   https://tools.ietf.org/html/rfc5869
 *
 * PBKDF2 Resources:
 *   https://en.wikipedia.org/wiki/PBKDF2
 *   https://tools.ietf.org/html/rfc2898
 *   https://tools.ietf.org/html/rfc2898#section-5.2
 *   https://tools.ietf.org/html/rfc6070
 *   https://www.emc.com/collateral/white-papers/h11302-pkcs5v2-1-password-based-cryptography-standard-wp.pdf
 *   http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
 *
 * Scrypt Resources:
 *   https://en.wikipedia.org/wiki/Scrypt
 *   http://www.tarsnap.com/scrypt.html
 *   http://www.tarsnap.com/scrypt/scrypt.pdf
 *   https://github.com/Tarsnap/scrypt/blob/master/lib/crypto/crypto_scrypt-ref.c
 */

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <torsion/hash.h>
#include <torsion/kdf.h>
#include <torsion/util.h>
#include "bio.h"

/*
 * Prototypes
 */

static void blkcpy(uint8_t *, uint8_t *, size_t);
static void blkxor(uint8_t *, uint8_t *, size_t);
static void salsa20_8(uint8_t *);
static void blockmix_salsa8(uint8_t *, uint8_t *, size_t);
static uint64_t integerify(uint8_t *, size_t);
static void smix(uint8_t *, size_t, uint64_t, uint8_t *, uint8_t *);

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
            size_t iv_len) {
  size_t hash_size = hash_output_size(type);
  unsigned char prev[HASH_MAX_OUTPUT_SIZE];
  size_t prev_pos, avail, want, use;
  size_t prev_len = 0;
  size_t key_pos = 0;
  size_t iv_pos = 0;
  hash_t hash;

  if (salt_len > 8)
    salt_len = 8;

  if (!hash_has_backend(type))
    return 0;

  if (salt_len != 0 && salt_len != 8)
    return 0;

  while (key_pos < key_len || iv_pos < iv_len) {
    hash_init(&hash, type);
    hash_update(&hash, prev, prev_len);
    hash_update(&hash, passwd, passwd_len);
    hash_update(&hash, salt, salt_len);
    hash_final(&hash, prev, hash_size);

    prev_pos = 0;
    prev_len = hash_size;

    if (key_pos < key_len) {
      avail = prev_len - prev_pos;
      want = key_len - key_pos;
      use = avail < want ? avail : want;

      memcpy(key + key_pos, prev + prev_pos, use);

      key_pos += use;
      prev_pos += use;
    }

    if (iv_pos < iv_len) {
      avail = prev_len - prev_pos;
      want = iv_len - iv_pos;
      use = avail < want ? avail : want;

      memcpy(iv + iv_pos, prev + prev_pos, use);

      iv_pos += use;
      prev_pos += use;
    }
  }

  cleanse(prev, sizeof(prev));
  cleanse(&hash, sizeof(hash));

  return 1;
}

/*
 * HKDF
 */

int
hkdf_extract(unsigned char *out, int type,
             const unsigned char *ikm, size_t ikm_len,
             const unsigned char *salt, size_t salt_len) {
  hmac_t hmac;

  if (!hash_has_backend(type))
    return 0;

  hmac_init(&hmac, type, salt, salt_len);
  hmac_update(&hmac, ikm, ikm_len);
  hmac_final(&hmac, out);

  return 1;
}

int
hkdf_expand(unsigned char *out,
            int type,
            const unsigned char *prk,
            const unsigned char *info,
            size_t info_len,
            size_t len) {
  size_t hash_size = hash_output_size(type);
  unsigned char prev[HASH_MAX_OUTPUT_SIZE];
  unsigned char ctr = 0;
  size_t prev_len = 0;
  hmac_t pmac, hmac;
  size_t i, blocks;

  if (!hash_has_backend(type))
    return 0;

  if (len + hash_size - 1 < len)
    return 0;

  blocks = (len + hash_size - 1) / hash_size;

  if (blocks > 255)
    return 0;

  if (len == 0)
    return 1;

  hmac_init(&pmac, type, prk, hash_size);

  for (i = 0; i < blocks; i++) {
    ctr += 1;

    memcpy(&hmac, &pmac, sizeof(pmac));
    hmac_update(&hmac, prev, prev_len);
    hmac_update(&hmac, info, info_len);
    hmac_update(&hmac, &ctr, 1);
    hmac_final(&hmac, prev);

    prev_len = hash_size;

    if (hash_size > len)
      hash_size = len;

    memcpy(out, prev, hash_size);

    out += hash_size;
    len -= hash_size;
  }

  cleanse(prev, sizeof(prev));
  cleanse(&pmac, sizeof(pmac));
  cleanse(&hmac, sizeof(hmac));

  return 1;
}

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
              size_t len) {
  size_t hash_size = hash_output_size(type);
  unsigned char block[HASH_MAX_OUTPUT_SIZE];
  unsigned char mac[HASH_MAX_OUTPUT_SIZE];
  unsigned char ctr[4];
  hmac_t pmac, smac, hmac;
  size_t i, k, blocks;
  uint32_t j;

  if (!hash_has_backend(type))
    return 0;

  if (len + hash_size - 1 < len)
    return 0;

  blocks = (len + hash_size - 1) / hash_size;

  if (blocks > UINT32_MAX)
    return 0;

  if (len == 0)
    return 1;

  hmac_init(&pmac, type, pass, pass_len);

  memcpy(&smac, &pmac, sizeof(pmac));
  hmac_update(&smac, salt, salt_len);

  for (i = 0; i < blocks; i++) {
    write32be(ctr, i + 1);

    memcpy(&hmac, &smac, sizeof(smac));
    hmac_update(&hmac, ctr, 4);
    hmac_final(&hmac, block);

    memcpy(mac, block, hash_size);

    for (j = 1; j < iter; j++) {
      memcpy(&hmac, &pmac, sizeof(pmac));
      hmac_update(&hmac, mac, hash_size);
      hmac_final(&hmac, mac);

      for (k = 0; k < hash_size; k++)
        block[k] ^= mac[k];
    }

    if (hash_size > len)
      hash_size = len;

    memcpy(out, block, hash_size);

    out += hash_size;
    len -= hash_size;
  }

  cleanse(block, sizeof(block));
  cleanse(mac, sizeof(mac));
  cleanse(&pmac, sizeof(pmac));
  cleanse(&smac, sizeof(smac));
  cleanse(&hmac, sizeof(hmac));

  return 1;
}

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
              size_t len) {
  int t = HASH_SHA256;
  uint8_t *B = NULL;
  uint8_t *V = NULL;
  uint8_t *XY = NULL;
  uint32_t i;
  int ret = 0;

  if (N > UINT32_MAX)
    return 0;

  if ((uint64_t)r * (uint64_t)p >= (UINT64_C(1) << 25))
    return 0;

  if (r >= (UINT32_C(1) << 24))
    return 0;

  if ((uint64_t)r * N >= (UINT64_C(1) << 25))
    return 0;

  if (N == 0 || (N & (N - 1)) != 0)
    return 0;

  if (len == 0)
    return 1;

  B = torsion_malloc_unsafe(128 * r * p);
  XY = torsion_malloc_unsafe(256 * r);
  V = torsion_malloc_unsafe(128 * r * N);

  if (B == NULL || XY == NULL || V == NULL)
    goto fail;

  if (!pbkdf2_derive(B, t, pass, pass_len, salt, salt_len, 1, p * 128 * r))
    goto fail;

  for (i = 0; i < p; i++)
    smix(&B[i * 128 * r], r, N, V, XY);

  if (!pbkdf2_derive(out, t, pass, pass_len, B, p * 128 * r, 1, len))
    goto fail;

  ret = 1;
fail:
  if (B != NULL) {
    cleanse(B, 128 * r * p);
    torsion_free(B);
  }

  if (XY != NULL) {
    cleanse(XY, 256 * r);
    torsion_free(XY);
  }

  if (V != NULL) {
    cleanse(V, 128 * r * N);
    torsion_free(V);
  }

  return ret;
}

static void
blkcpy(uint8_t *dest, uint8_t *src, size_t len) {
  memcpy(dest, src, len);
}

static void
blkxor(uint8_t *dest, uint8_t *src, size_t len) {
  size_t i;

  for (i = 0; i < len; i++)
    dest[i] ^= src[i];
}

static void
salsa20_8(uint8_t *B) {
  uint32_t B32[16];
  uint32_t x[16];
  size_t i;

  /* Convert little-endian values in. */
  for (i = 0; i < 16; i++)
    B32[i] = read32le(&B[i * 4]);

  /* Compute x = doubleround^4(B32). */
  for (i = 0; i < 16; i++)
    x[i] = B32[i];

  for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
    /* Operate on columns. */
    x[ 4] ^= R(x[ 0] + x[12],  7);
    x[ 8] ^= R(x[ 4] + x[ 0],  9);
    x[12] ^= R(x[ 8] + x[ 4], 13);
    x[ 0] ^= R(x[12] + x[ 8], 18);

    x[ 9] ^= R(x[ 5] + x[ 1],  7);
    x[13] ^= R(x[ 9] + x[ 5],  9);
    x[ 1] ^= R(x[13] + x[ 9], 13);
    x[ 5] ^= R(x[ 1] + x[13], 18);

    x[14] ^= R(x[10] + x[ 6],  7);
    x[ 2] ^= R(x[14] + x[10],  9);
    x[ 6] ^= R(x[ 2] + x[14], 13);
    x[10] ^= R(x[ 6] + x[ 2], 18);

    x[ 3] ^= R(x[15] + x[11],  7);
    x[ 7] ^= R(x[ 3] + x[15],  9);
    x[11] ^= R(x[ 7] + x[ 3], 13);
    x[15] ^= R(x[11] + x[ 7], 18);

    /* Operate on rows. */
    x[ 1] ^= R(x[ 0] + x[ 3],  7);
    x[ 2] ^= R(x[ 1] + x[ 0],  9);
    x[ 3] ^= R(x[ 2] + x[ 1], 13);
    x[ 0] ^= R(x[ 3] + x[ 2], 18);

    x[ 6] ^= R(x[ 5] + x[ 4],  7);
    x[ 7] ^= R(x[ 6] + x[ 5],  9);
    x[ 4] ^= R(x[ 7] + x[ 6], 13);
    x[ 5] ^= R(x[ 4] + x[ 7], 18);

    x[11] ^= R(x[10] + x[ 9],  7);
    x[ 8] ^= R(x[11] + x[10],  9);
    x[ 9] ^= R(x[ 8] + x[11], 13);
    x[10] ^= R(x[ 9] + x[ 8], 18);

    x[12] ^= R(x[15] + x[14],  7);
    x[13] ^= R(x[12] + x[15],  9);
    x[14] ^= R(x[13] + x[12], 13);
    x[15] ^= R(x[14] + x[13], 18);
#undef R
  }

  /* Compute B32 = B32 + x. */
  for (i = 0; i < 16; i++)
    B32[i] += x[i];

  /* Convert little-endian values out. */
  for (i = 0; i < 16; i++)
    write32le(&B[4 * i], B32[i]);
}

static void
blockmix_salsa8(uint8_t *B, uint8_t *Y, size_t r) {
  uint8_t X[64];
  size_t i;

  /* 1: X <-- B_{2r - 1} */
  blkcpy(X, &B[(2 * r - 1) * 64], 64);

  /* 2: for i = 0 to 2r - 1 do */
  for (i = 0; i < 2 * r; i++) {
    /* 3: X <-- H(X \xor B_i) */
    blkxor(X, &B[i * 64], 64);
    salsa20_8(X);

    /* 4: Y_i <-- X */
    blkcpy(&Y[i * 64], X, 64);
  }

  /* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
  for (i = 0; i < r; i++)
    blkcpy(&B[i * 64], &Y[(i * 2) * 64], 64);

  for (i = 0; i < r; i++)
    blkcpy(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
}

static uint64_t
integerify(uint8_t *B, size_t r) {
  uint8_t *X = &B[(2 * r - 1) * 64];

  return read64le(X);
}

static void
smix(uint8_t *B, size_t r, uint64_t N, uint8_t *V, uint8_t *XY) {
  uint8_t *X = XY;
  uint8_t *Y = &XY[128 * r];
  uint64_t i;
  uint64_t j;

  /* 1: X <-- B */
  blkcpy(X, B, 128 * r);

  /* 2: for i = 0 to N - 1 do */
  for (i = 0; i < N; i++) {
    /* 3: V_i <-- X */
    blkcpy(&V[i * (128 * r)], X, 128 * r);

    /* 4: X <-- H(X) */
    blockmix_salsa8(X, Y, r);
  }

  /* 6: for i = 0 to N - 1 do */
  for (i = 0; i < N; i++) {
    /* 7: j <-- Integerify(X) mod N */
    j = integerify(X, r) & (N - 1);

    /* 8: X <-- H(X \xor V_j) */
    blkxor(X, &V[j * (128 * r)], 128 * r);
    blockmix_salsa8(X, Y, r);
  }

  /* 10: B' <-- X */
  blkcpy(B, X, 128 * r);
}
