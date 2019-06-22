#include "hash.h"

#define MAKE_BLAKE(HASH, NAME, TITLE, SIZE, BLOCK_SIZE)              \
static void                                                          \
NAME##_init(HASH##_ctx *ctx) {                                       \
  (void)HASH##_init(ctx, SIZE);                                      \
}                                                                    \
                                                                     \
static void                                                          \
NAME##_update(HASH##_ctx *ctx, size_t length, const uint8_t *data) { \
  (void)HASH##_update(ctx, (const void *)data, length);              \
}                                                                    \
                                                                     \
static void                                                          \
NAME##_digest(HASH##_ctx *ctx, size_t length, uint8_t *digest) {     \
  uint8_t *out[SIZE];                                                \
  (void)HASH##_final(ctx, (void *)out, SIZE);                        \
  memcpy(digest, out, length < SIZE ? length : SIZE);                \
}                                                                    \
                                                                     \
const struct nettle_hash nettle_##NAME = {                           \
  TITLE,                                                             \
  sizeof(HASH##_ctx),                                                \
  SIZE,                                                              \
  BLOCK_SIZE,                                                        \
  (nettle_hash_init_func *)NAME##_init,                              \
  (nettle_hash_update_func *)NAME##_update,                          \
  (nettle_hash_digest_func *)NAME##_digest                           \
};

MAKE_BLAKE(bcrypto_blake2b, blake2b160, "blake2b160", 20, 128)
MAKE_BLAKE(bcrypto_blake2b, blake2b256, "blake2b256", 32, 128)
MAKE_BLAKE(bcrypto_blake2b, blake2b384, "blake2b384", 48, 128)
MAKE_BLAKE(bcrypto_blake2b, blake2b512, "blake2b512", 64, 128)

MAKE_BLAKE(bcrypto_blake2s, blake2s128, "blake2s128", 16, 64)
MAKE_BLAKE(bcrypto_blake2s, blake2s160, "blake2s160", 20, 64)
MAKE_BLAKE(bcrypto_blake2s, blake2s224, "blake2s224", 28, 64)
MAKE_BLAKE(bcrypto_blake2s, blake2s256, "blake2s256", 32, 64)

#undef MAKE_BLAKE

#define MAKE_KECCAK(NAME, TITLE, BITS, SIZE, BLOCK_SIZE, PAD)        \
static void                                                          \
NAME##_init(bcrypto_keccak_ctx *ctx) {                               \
  assert(bcrypto_keccak_init(ctx, BITS) == 1);                       \
}                                                                    \
                                                                     \
static void                                                          \
NAME##_update(bcrypto_keccak_ctx *ctx,                               \
              size_t length, const uint8_t *data) {                  \
  bcrypto_keccak_update(ctx, data, length);                          \
}                                                                    \
                                                                     \
static void                                                          \
NAME##_digest(bcrypto_keccak_ctx *ctx,                               \
              size_t length, uint8_t *data) {                        \
  assert(bcrypto_keccak_final(ctx, data, NULL, length, PAD) == 1);   \
}                                                                    \
                                                                     \
const struct nettle_hash nettle_##NAME = {                           \
  TITLE,                                                             \
  sizeof(bcrypto_keccak_ctx),                                        \
  SIZE,                                                              \
  BLOCK_SIZE,                                                        \
  (nettle_hash_init_func *)NAME##_init,                              \
  (nettle_hash_update_func *)NAME##_update,                          \
  (nettle_hash_digest_func *)NAME##_digest                           \
};

MAKE_KECCAK(keccak224, "keccak224", 224, 28, 144, 0x01)
MAKE_KECCAK(keccak256, "keccak256", 256, 32, 136, 0x01)
MAKE_KECCAK(keccak384, "keccak384", 384, 48, 104, 0x01)
MAKE_KECCAK(keccak512, "keccak512", 512, 64, 72, 0x01)

MAKE_KECCAK(shake128, "shake128", 128, 16, 168, 0x1f)
MAKE_KECCAK(shake256, "shake256", 256, 32, 72, 0x1f)

#undef MAKE_KECCAK

void
bcrypto_hmac_set_key(bcrypto_hmac_t *hmac,
                     size_t key_length, const uint8_t *key) {
  hmac_set_key(hmac->outer, hmac->inner,
               hmac->state, hmac->hash,
               key_length, key);
}

void
bcrypto_hmac_update(bcrypto_hmac_t *hmac,
                    size_t length, const uint8_t *data) {
  hmac_update(hmac->state, hmac->hash, length, data);
}

void
bcrypto_hmac_digest(bcrypto_hmac_t *hmac,
                    size_t length, uint8_t *digest) {
  hmac_digest(hmac->outer, hmac->inner,
              hmac->state, hmac->hash,
              length, digest);
}

int
bcrypto_hash_type(const char *alg) {
  if (alg == NULL)
    return 0;

  if (strcmp(alg, "BLAKE2B160") == 0)
    return BCRYPTO_HASH_BLAKE2B160;

  if (strcmp(alg, "BLAKE2B256") == 0)
    return BCRYPTO_HASH_BLAKE2B256;

  if (strcmp(alg, "BLAKE2B384") == 0)
    return BCRYPTO_HASH_BLAKE2B384;

  if (strcmp(alg, "BLAKE2B512") == 0)
    return BCRYPTO_HASH_BLAKE2B512;

  if (strcmp(alg, "BLAKE2S128") == 0)
    return BCRYPTO_HASH_BLAKE2S128;

  if (strcmp(alg, "BLAKE2S160") == 0)
    return BCRYPTO_HASH_BLAKE2S160;

  if (strcmp(alg, "BLAKE2S224") == 0)
    return BCRYPTO_HASH_BLAKE2S224;

  if (strcmp(alg, "BLAKE2S256") == 0)
    return BCRYPTO_HASH_BLAKE2S256;

  if (strcmp(alg, "GOST94") == 0)
    return BCRYPTO_HASH_GOST94;

  if (strcmp(alg, "KECCAK224") == 0)
    return BCRYPTO_HASH_KECCAK224;

  if (strcmp(alg, "KECCAK256") == 0)
    return BCRYPTO_HASH_KECCAK256;

  if (strcmp(alg, "KECCAK384") == 0)
    return BCRYPTO_HASH_KECCAK384;

  if (strcmp(alg, "KECCAK512") == 0)
    return BCRYPTO_HASH_KECCAK512;

  if (strcmp(alg, "MD2") == 0)
    return BCRYPTO_HASH_MD2;

  if (strcmp(alg, "MD4") == 0)
    return BCRYPTO_HASH_MD4;

  if (strcmp(alg, "MD5") == 0)
    return BCRYPTO_HASH_MD5;

  if (strcmp(alg, "MD5SHA1") == 0)
    return BCRYPTO_HASH_MD5SHA1;

  if (strcmp(alg, "RIPEMD160") == 0)
    return BCRYPTO_HASH_RIPEMD160;

  if (strcmp(alg, "SHA1") == 0)
    return BCRYPTO_HASH_SHA1;

  if (strcmp(alg, "SHA224") == 0)
    return BCRYPTO_HASH_SHA224;

  if (strcmp(alg, "SHA256") == 0)
    return BCRYPTO_HASH_SHA256;

  if (strcmp(alg, "SHA384") == 0)
    return BCRYPTO_HASH_SHA384;

  if (strcmp(alg, "SHA512") == 0)
    return BCRYPTO_HASH_SHA512;

  if (strcmp(alg, "SHA3_224") == 0)
    return BCRYPTO_HASH_SHA3_224;

  if (strcmp(alg, "SHA3_256") == 0)
    return BCRYPTO_HASH_SHA3_256;

  if (strcmp(alg, "SHA3_384") == 0)
    return BCRYPTO_HASH_SHA3_384;

  if (strcmp(alg, "SHA3_512") == 0)
    return BCRYPTO_HASH_SHA3_512;

  if (strcmp(alg, "SHAKE128") == 0)
    return BCRYPTO_HASH_SHAKE128;

  if (strcmp(alg, "SHAKE256") == 0)
    return BCRYPTO_HASH_SHAKE256;

  if (strcmp(alg, "WHIRLPOOL") == 0)
    return BCRYPTO_HASH_WHIRLPOOL;

  return 0;
}

size_t
bcrypto_hash_size(int type) {
  switch (type) {
    case BCRYPTO_HASH_BLAKE2B160:
      return 20;
    case BCRYPTO_HASH_BLAKE2B256:
      return 32;
    case BCRYPTO_HASH_BLAKE2B384:
      return 48;
    case BCRYPTO_HASH_BLAKE2B512:
      return 64;
    case BCRYPTO_HASH_BLAKE2S128:
      return 16;
    case BCRYPTO_HASH_BLAKE2S160:
      return 20;
    case BCRYPTO_HASH_BLAKE2S224:
      return 28;
    case BCRYPTO_HASH_BLAKE2S256:
      return 32;
    case BCRYPTO_HASH_GOST94:
      return 32;
    case BCRYPTO_HASH_KECCAK224:
      return 28;
    case BCRYPTO_HASH_KECCAK256:
      return 32;
    case BCRYPTO_HASH_KECCAK384:
      return 48;
    case BCRYPTO_HASH_KECCAK512:
      return 64;
    case BCRYPTO_HASH_MD2:
      return 16;
    case BCRYPTO_HASH_MD4:
      return 16;
    case BCRYPTO_HASH_MD5:
      return 16;
    case BCRYPTO_HASH_MD5SHA1:
      return 36;
    case BCRYPTO_HASH_RIPEMD160:
      return 20;
    case BCRYPTO_HASH_SHA1:
      return 20;
    case BCRYPTO_HASH_SHA224:
      return 28;
    case BCRYPTO_HASH_SHA256:
      return 32;
    case BCRYPTO_HASH_SHA384:
      return 48;
    case BCRYPTO_HASH_SHA512:
      return 64;
    case BCRYPTO_HASH_SHA3_224:
      return 28;
    case BCRYPTO_HASH_SHA3_256:
      return 32;
    case BCRYPTO_HASH_SHA3_384:
      return 48;
    case BCRYPTO_HASH_SHA3_512:
      return 64;
    case BCRYPTO_HASH_SHAKE128:
      return 16;
    case BCRYPTO_HASH_SHAKE256:
      return 32;
    case BCRYPTO_HASH_WHIRLPOOL:
      return 64;
    default:
      return 0;
  }
}

const struct nettle_hash *
bcrypto_hash_get(int type) {
  switch (type) {
    case BCRYPTO_HASH_BLAKE2B160:
      return &nettle_blake2b160;
    case BCRYPTO_HASH_BLAKE2B256:
      return &nettle_blake2b256;
    case BCRYPTO_HASH_BLAKE2B384:
      return &nettle_blake2b384;
    case BCRYPTO_HASH_BLAKE2B512:
      return &nettle_blake2b512;
    case BCRYPTO_HASH_BLAKE2S128:
      return &nettle_blake2s128;
    case BCRYPTO_HASH_BLAKE2S160:
      return &nettle_blake2s160;
    case BCRYPTO_HASH_BLAKE2S224:
      return &nettle_blake2s224;
    case BCRYPTO_HASH_BLAKE2S256:
      return &nettle_blake2s256;
    case BCRYPTO_HASH_GOST94:
      return &nettle_gosthash94;
    case BCRYPTO_HASH_KECCAK224:
      return &nettle_keccak224;
    case BCRYPTO_HASH_KECCAK256:
      return &nettle_keccak256;
    case BCRYPTO_HASH_KECCAK384:
      return &nettle_keccak384;
    case BCRYPTO_HASH_KECCAK512:
      return &nettle_keccak512;
    case BCRYPTO_HASH_MD2:
      return &nettle_md2;
    case BCRYPTO_HASH_MD4:
      return &nettle_md4;
    case BCRYPTO_HASH_MD5:
      return &nettle_md5;
    case BCRYPTO_HASH_MD5SHA1:
      return NULL;
    case BCRYPTO_HASH_RIPEMD160:
      return &nettle_ripemd160;
    case BCRYPTO_HASH_SHA1:
      return &nettle_sha1;
    case BCRYPTO_HASH_SHA224:
      return &nettle_sha224;
    case BCRYPTO_HASH_SHA256:
      return &nettle_sha256;
    case BCRYPTO_HASH_SHA384:
      return &nettle_sha384;
    case BCRYPTO_HASH_SHA512:
      return &nettle_sha512;
    case BCRYPTO_HASH_SHA3_224:
      return &nettle_sha3_224;
    case BCRYPTO_HASH_SHA3_256:
      return &nettle_sha3_256;
    case BCRYPTO_HASH_SHA3_384:
      return &nettle_sha3_384;
    case BCRYPTO_HASH_SHA3_512:
      return &nettle_sha3_512;
    case BCRYPTO_HASH_SHAKE128:
      return &nettle_shake128;
    case BCRYPTO_HASH_SHAKE256:
      return &nettle_shake256;
    case BCRYPTO_HASH_WHIRLPOOL:
      return NULL;
    default:
      return NULL;
  }
}
