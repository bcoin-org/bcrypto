#include "../nettle/sha2.h"

typedef struct sha512_ctx bcrypto_ed25519_hash_t;

static void
bcrypto_ed25519_hash_init(bcrypto_ed25519_hash_t *ctx) {
  sha512_init(ctx);
}

static void
bcrypto_ed25519_hash_update(
  bcrypto_ed25519_hash_t *ctx,
  const uint8_t *in,
  size_t inlen
) {
  sha512_update(ctx, inlen, in);
}

static void
bcrypto_ed25519_hash_final(bcrypto_ed25519_hash_t *ctx, uint8_t *hash) {
  sha512_digest(ctx, 64, hash);
}

static void
bcrypto_ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
  struct sha512_ctx ctx;
  sha512_init(&ctx);
  sha512_update(&ctx, inlen, in);
  sha512_digest(&ctx, 64, hash);
}
