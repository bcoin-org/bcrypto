#ifndef _HSK_HASH_H
#define _HSK_HASH_H

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../blake2b/blake2b.h"
#include "../blake2s/blake2s.h"
#include "../keccak/keccak.h"
#include "../nettle/md2.h"
#include "../nettle/md4.h"
#include "../nettle/md5.h"
#include "../nettle/gosthash94.h"
#include "../nettle/ripemd160.h"
#include "../nettle/sha1.h"
#include "../nettle/sha2.h"
#include "../nettle/sha3.h"
#include "../nettle/hmac.h"
#include "../nettle/nettle-meta.h"
#include "../nettle/nettle-types.h"
#include "../nettle/nettle-internal.h"

#define BCRYPTO_HASH_BLAKE2B160 1
#define BCRYPTO_HASH_BLAKE2B256 2
#define BCRYPTO_HASH_BLAKE2B384 3
#define BCRYPTO_HASH_BLAKE2B512 4
#define BCRYPTO_HASH_BLAKE2S128 5
#define BCRYPTO_HASH_BLAKE2S160 6
#define BCRYPTO_HASH_BLAKE2S224 7
#define BCRYPTO_HASH_BLAKE2S256 8
#define BCRYPTO_HASH_GOST94 9
#define BCRYPTO_HASH_KECCAK224 10
#define BCRYPTO_HASH_KECCAK256 11
#define BCRYPTO_HASH_KECCAK384 12
#define BCRYPTO_HASH_KECCAK512 13
#define BCRYPTO_HASH_MD2 14
#define BCRYPTO_HASH_MD4 15
#define BCRYPTO_HASH_MD5 16
#define BCRYPTO_HASH_MD5SHA1 17
#define BCRYPTO_HASH_RIPEMD160 18
#define BCRYPTO_HASH_SHA1 19
#define BCRYPTO_HASH_SHA224 20
#define BCRYPTO_HASH_SHA256 21
#define BCRYPTO_HASH_SHA384 22
#define BCRYPTO_HASH_SHA512 23
#define BCRYPTO_HASH_SHA3_224 24
#define BCRYPTO_HASH_SHA3_256 25
#define BCRYPTO_HASH_SHA3_384 26
#define BCRYPTO_HASH_SHA3_512 27
#define BCRYPTO_HASH_SHAKE128 28
#define BCRYPTO_HASH_SHAKE256 29
#define BCRYPTO_HASH_WHIRLPOOL 30

#define BCRYPTO_HASH_MIN 1
#define BCRYPTO_HASH_MAX 30
#define BCRYPTO_HASH_MAX_SIZE NETTLE_MAX_HASH_DIGEST_SIZE
#define BCRYPTO_HASH_MAX_CONTEXT_SIZE NETTLE_MAX_HASH_CONTEXT_SIZE

#if defined(__cplusplus)
extern "C" {
#endif

int
bcrypto_hash_type(const char *alg);

size_t
bcrypto_hash_size(int type);

const struct nettle_hash *
bcrypto_hash_get(int type);

typedef struct bcrypto_hmac_s {
  const struct nettle_hash *hash;
  uint8_t outer[BCRYPTO_HASH_MAX_CONTEXT_SIZE];
  uint8_t inner[BCRYPTO_HASH_MAX_CONTEXT_SIZE];
  uint8_t state[BCRYPTO_HASH_MAX_CONTEXT_SIZE];
} bcrypto_hmac_t;

void
bcrypto_hmac_set_key(bcrypto_hmac_t *hmac,
                     size_t key_length, const uint8_t *key);

void
bcrypto_hmac_update(bcrypto_hmac_t *hmac,
                    size_t length, const uint8_t *data);

void
bcrypto_hmac_digest(bcrypto_hmac_t *hmac,
                    size_t length, uint8_t *digest);

#if defined(__cplusplus)
}
#endif

#endif
