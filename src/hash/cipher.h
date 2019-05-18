#ifndef _HSK_CIPHER_H
#define _HSK_CIPHER_H

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../nettle/aes.h"
#include "../nettle/arctwo.h"
#include "../nettle/blowfish.h"
#include "../nettle/camellia.h"
#include "../nettle/des.h"
#include "../nettle/twofish.h"
#include "../nettle/cbc.h"
#include "../nettle/cfb.h"
#include "../nettle/ctr.h"
#include "../nettle/gcm.h"
#include "../nettle/nettle-internal.h"
#include "../nettle/memxor.h"

#define BCRYPTO_CIPHER_AES128 1
#define BCRYPTO_CIPHER_AES192 2
#define BCRYPTO_CIPHER_AES256 3
#define BCRYPTO_CIPHER_BLOWFISH 4
#define BCRYPTO_CIPHER_CAMELLIA128 5
#define BCRYPTO_CIPHER_CAMELLIA192 6
#define BCRYPTO_CIPHER_CAMELLIA256 7
#define BCRYPTO_CIPHER_CAST5 8
#define BCRYPTO_CIPHER_DES 9
#define BCRYPTO_CIPHER_DES_EDE 10
#define BCRYPTO_CIPHER_DES_EDE3 11
#define BCRYPTO_CIPHER_IDEA 12
#define BCRYPTO_CIPHER_RC2 13
#define BCRYPTO_CIPHER_TWOFISH128 14
#define BCRYPTO_CIPHER_TWOFISH192 15
#define BCRYPTO_CIPHER_TWOFISH256 16

#define BCRYPTO_CIPHER_MIN 1
#define BCRYPTO_CIPHER_MAX 16
#define BCRYPTO_CIPHER_MAX_BLOCK_SIZE NETTLE_MAX_CIPHER_BLOCK_SIZE

#define BCRYPTO_MODE_ECB 1
#define BCRYPTO_MODE_CBC 2
#define BCRYPTO_MODE_CTR 3
#define BCRYPTO_MODE_CFB 4
#define BCRYPTO_MODE_OFB 5
#define BCRYPTO_MODE_GCM 6

#define BCRYPTO_MODE_MIN 1
#define BCRYPTO_MODE_MAX 6

#if defined(__cplusplus)
extern "C" {
#endif

/*

struct nettle_cipher
{
  const char *name;

  unsigned context_size;

  unsigned block_size;

  unsigned key_size;

  nettle_set_key_func *set_encrypt_key;
  nettle_set_key_func *set_decrypt_key;

  nettle_cipher_func *encrypt;
  nettle_cipher_func *decrypt;
};

struct nettle_aead
{
  const char *name;

  unsigned context_size;
  unsigned block_size;
  unsigned key_size;
  unsigned nonce_size;
  unsigned digest_size;

  nettle_set_key_func *set_encrypt_key;
  nettle_set_key_func *set_decrypt_key;
  nettle_set_key_func *set_nonce;
  nettle_hash_update_func *update;
  nettle_crypt_func *encrypt;
  nettle_crypt_func *decrypt;
  nettle_hash_digest_func *digest;
};
*/

typedef struct bcrypto_cipher_s {
  int type;
  const struct nettle_cipher *desc;
  const struct nettle_aead *aead;
  void *ctx;
  uint8_t state[BCRYPTO_CIPHER_MAX_BLOCK_SIZE];
  uint8_t block[BCRYPTO_CIPHER_MAX_BLOCK_SIZE];
  uint8_t last[BCRYPTO_CIPHER_MAX_BLOCK_SIZE];
  int mode;
  int encrypt;
  size_t block_pos;
} bcrypto_cipher_t;

size_t
bcrypto_cipher_block_size(int type);

size_t
bcrypto_cipher_key_size(int type);

const struct nettle_cipher *
bcrypto_cipher_get(int type);

const struct nettle_aead *
bcrypto_cipher_gcm(int type);

void
bcrypto_cipher_init(bcrypto_cipher_t *cipher);

int
bcrypto_cipher_setup(bcrypto_cipher_t *cipher, int type, int mode, int encrypt);

void
bcrypto_cipher_clear(bcrypto_cipher_t *cipher);

int
bcrypto_cipher_set_key(bcrypto_cipher_t *cipher,
                       const uint8_t *key, size_t length);

int
bcrypto_cipher_set_iv(bcrypto_cipher_t *cipher,
                      const uint8_t *iv, size_t length);

int
bcrypto_cipher_auth(bcrypto_cipher_t *cipher, const uint8_t *data, size_t len);

int
bcrypto_cipher_digest(bcrypto_cipher_t *cipher, uint8_t *data, size_t len);

size_t
bcrypto_cipher_update(bcrypto_cipher_t *cipher, uint8_t *dst,
                     const uint8_t *src, size_t length);

void
bcrypto_cipher_crypt(bcrypto_cipher_t *cipher, uint8_t *dst,
                     const uint8_t *src, size_t length);

int
bcrypto_cipher_final(bcrypto_cipher_t *cipher, uint8_t *out);

int
bcrypto_cipher_verify(bcrypto_cipher_t *cipher,
                      const uint8_t *expect, size_t len);

#if defined(__cplusplus)
}
#endif

#endif
