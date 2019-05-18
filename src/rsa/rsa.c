#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include <stdlib.h>
#include "rsa.h"

#include "../hash/hash.h"
#include "../nettle/rsa-internal.h"
#include "../nettle/rsa.h"
#include "../nettle/pss.h"
#include "../nettle/pss-mgf1.h"
#include "../nettle/bignum.h"
#include "../random/random.h"

static const char *PKCS1_PREFIXES[] = {
  /* NONE */ "",
  /* BLAKE2B160 */ "\x15\x30\x27\x30\x0f\x06\x0b\x2b\x06\x01\x04\x01\x8d\x3a\x0c\x02\x01\x05\x05\x00\x04\x14",
  /* BLAKE2B256 */ "\x15\x30\x33\x30\x0f\x06\x0b\x2b\x06\x01\x04\x01\x8d\x3a\x0c\x02\x01\x08\x05\x00\x04\x20",
  /* BLAKE2B384 */ "\x15\x30\x43\x30\x0f\x06\x0b\x2b\x06\x01\x04\x01\x8d\x3a\x0c\x02\x01\x0c\x05\x00\x04\x30",
  /* BLAKE2B512 */ "\x15\x30\x53\x30\x0f\x06\x0b\x2b\x06\x01\x04\x01\x8d\x3a\x0c\x02\x01\x10\x05\x00\x04\x40",
  /* BLAKE2S128 */ "\x15\x30\x23\x30\x0f\x06\x0b\x2b\x06\x01\x04\x01\x8d\x3a\x0c\x02\x02\x04\x05\x00\x04\x10",
  /* BLAKE2S160 */ "\x15\x30\x27\x30\x0f\x06\x0b\x2b\x06\x01\x04\x01\x8d\x3a\x0c\x02\x02\x05\x05\x00\x04\x14",
  /* BLAKE2S224 */ "\x15\x30\x2f\x30\x0f\x06\x0b\x2b\x06\x01\x04\x01\x8d\x3a\x0c\x02\x02\x07\x05\x00\x04\x1c",
  /* BLAKE2S256 */ "\x15\x30\x33\x30\x0f\x06\x0b\x2b\x06\x01\x04\x01\x8d\x3a\x0c\x02\x02\x08\x05\x00\x04\x20",
  /* GOST94 */ "\x10\x30\x2e\x30\x0a\x06\x06\x2a\x85\x03\x02\x02\x14\x05\x00\x04\x20",
  /* KECCAK224 */ "\x13\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x07\x05\x00\x04\x1c",
  /* KECCAK256 */ "\x13\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08\x05\x00\x04\x20",
  /* KECCAK384 */ "\x13\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09\x05\x00\x04\x30",
  /* KECCAK512 */ "\x13\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0a\x05\x00\x04\x40",
  /* MD2 */ "\x12\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02\x05\x00\x04\x10",
  /* MD4 */ "\x12\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x04\x05\x00\x04\x10",
  /* MD5 */ "\x12\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10",
  /* MD5SHA1 */ "\x00\x00",
  /* RIPEMD160 */ "\x10\x30\x22\x30\x0a\x06\x06\x28\xcf\x06\x03\x00\x31\x05\x00\x04\x14",
  /* SHA1 */ "\x0f\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
  /* SHA224 */ "\x13\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c",
  /* SHA256 */ "\x13\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
  /* SHA384 */ "\x13\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
  /* SHA512 */ "\x13\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
  /* SHA3_224 */ "\x13\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x07\x05\x00\x04\x1c",
  /* SHA3_256 */ "\x13\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08\x05\x00\x04\x20",
  /* SHA3_384 */ "\x13\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09\x05\x00\x04\x30",
  /* SHA3_512 */ "\x13\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0a\x05\x00\x04\x40",
  /* SHAKE128 */ "\x13\x30\x21\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0b\x05\x00\x04\x10",
  /* SHAKE256 */ "\x13\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0c\x05\x00\x04\x20",
  /* WHIRLPOOL */ "\x10\x30\x4e\x30\x0a\x06\x06\x28\xcf\x06\x03\x00\x37\x05\x00\x04\x40"
};

static inline size_t
rsa_mpz_bitlen(const mpz_t n) {
  if (mpz_sgn(n) == 0)
    return 0;

  return mpz_sizeinbase(n, 2);
}

#define rsa_mpz_bytelen(n) \
  (rsa_mpz_bitlen((n)) + 7) / 8

#define rsa_mpz_import(ret, data, len) \
  mpz_import((ret), (len), 1, sizeof((data)[0]), 0, 0, (data))

#define rsa_mpz_export(data, size, n) \
  mpz_export((data), (size), 1, sizeof((data)[0]), 0, 0, (n));

static inline void
rsa_mpz_pad(void *out, size_t size, const mpz_t n) {
  size_t len = rsa_mpz_bytelen(n);

  assert(len <= size);

  size_t pos = size - len;

  memset(out, 0x00, pos);

  rsa_mpz_export(out + pos, NULL, n);
}

static int
bcrypto_rsa_sane_pubkey(const struct rsa_public_key *pub) {
  size_t nb = rsa_mpz_bitlen(pub->n);

  if (nb < BCRYPTO_RSA_MIN_BITS || nb > BCRYPTO_RSA_MAX_BITS)
    return 0;

  size_t eb = rsa_mpz_bitlen(pub->e);

  if (eb < BCRYPTO_RSA_MIN_EXP_BITS || eb > BCRYPTO_RSA_MAX_EXP_BITS)
    return 0;

  if (mpz_even_p(pub->e))
    return 0;

  return 1;
}

static int
bcrypto_rsa_sane_privkey(const struct rsa_private_key *priv, const struct rsa_public_key *pub) {
  if (!bcrypto_rsa_sane_pubkey(pub))
    return 0;

  size_t nb = rsa_mpz_bitlen(pub->n);
  size_t db = rsa_mpz_bitlen(priv->d);

  if (db == 0 || db > nb)
    return 0;

  size_t pb = rsa_mpz_bitlen(priv->p);
  size_t qb = rsa_mpz_bitlen(priv->q);

  if (nb > pb + qb)
    return 0;

  size_t dpb = rsa_mpz_bitlen(priv->a);

  if (dpb == 0 || dpb > pb)
    return 0;

  size_t dqb = rsa_mpz_bitlen(priv->b);

  if (dqb == 0 || dqb > qb)
    return 0;

  size_t qib = rsa_mpz_bitlen(priv->c);

  if (qib == 0 || qib > pb)
    return 0;

  return 1;
}

static int
bcrypto_rsa_sane_compute(const struct rsa_private_key *priv,
                         const struct rsa_public_key *pub) {
  size_t nb = rsa_mpz_bitlen(pub->n);
  size_t eb = rsa_mpz_bitlen(pub->e);
  size_t db = rsa_mpz_bitlen(priv->d);
  size_t pb = rsa_mpz_bitlen(priv->p);
  size_t qb = rsa_mpz_bitlen(priv->q);
  size_t dpb = rsa_mpz_bitlen(priv->a);
  size_t dqb = rsa_mpz_bitlen(priv->b);
  size_t qib = rsa_mpz_bitlen(priv->c);

  if (pb == 0 || qb == 0)
    return 0;

  if (eb == 0 && db == 0)
    return 0;

  if (nb != 0) {
    if (nb < BCRYPTO_RSA_MIN_BITS || nb > BCRYPTO_RSA_MAX_BITS)
      return 0;

    if (nb > pb + qb)
      return 0;
  }

  if (eb != 0) {
    if (eb < BCRYPTO_RSA_MIN_EXP_BITS || eb > BCRYPTO_RSA_MAX_EXP_BITS)
      return 0;

    if (mpz_even_p(pub->e))
      return 0;
  }

  if (db != 0) {
    if (db > pb + qb)
      return 0;
  }

  if (dpb != 0) {
    if (dpb > pb)
      return 0;
  }

  if (dqb != 0) {
    if (dqb > qb)
      return 0;
  }

  if (qib != 0) {
    if (qib > pb)
      return 0;
  }

  return 1;
}

static int
bcrypto_rsa_needs_compute(const struct rsa_private_key *priv,
                          const struct rsa_public_key *pub) {
  return rsa_mpz_bitlen(pub->n) == 0
      || rsa_mpz_bitlen(pub->e) == 0
      || rsa_mpz_bitlen(priv->d) == 0
      || rsa_mpz_bitlen(priv->a) == 0
      || rsa_mpz_bitlen(priv->b) == 0
      || rsa_mpz_bitlen(priv->c) == 0;
}

#ifdef BCRYPTO_WASM

#define READINT(n, p) do {                \
  size = ((size_t)(p)[1] << 16) | (p)[0]; \
  rsa_mpz_import((n), (p) + 2, size);     \
  (p) += 2 + size;                        \
} while (0)                               \

static void
bcrypto_rsa_key2priv(struct rsa_private_key *out_priv,
                     struct rsa_private_key *out_pub,
                     const bcrypto_rsa_key_t *priv) {
  size_t size = 0;
  uint8_t *p = priv;

  READINT(out_pub->n, p);
  READINT(out_pub->e, p);
  READINT(out_priv->d, p);
  READINT(out_priv->p, p);
  READINT(out_priv->q, p);
  READINT(out_priv->a, p);
  READINT(out_priv->b, p);
  READINT(out_priv->c, p);

  out_priv->size = rsa_mpz_bytelen(out_pub->n);
  out_pub->size = out_priv->size;
}

static void
bcrypto_rsa_key2pub(struct rsa_public_key *out, const bcrypto_rsa_key_t *pub) {
  size_t size = 0;
  uint8_t *p = priv;

  READINT(out->n, p);
  READINT(out->e, p);

  out->size = rsa_mpz_bytelen(out->n);
}

#undef READINT

static void
bcrypto_rsa_priv2key(bcrypto_rsa_key_t *out,
                     const struct rsa_private_key *priv,
                     const struct rsa_public_key *pub) {
  size_t nl = rsa_mpz_bytelen(pub->n);
  size_t el = rsa_mpz_bytelen(pub->e);
  size_t dl = rsa_mpz_bytelen(priv->d);
  size_t pl = rsa_mpz_bytelen(priv->p);
  size_t ql = rsa_mpz_bytelen(priv->q);
  size_t dpl = rsa_mpz_bytelen(priv->a);
  size_t dql = rsa_mpz_bytelen(priv->b);
  size_t qil = rsa_mpz_bytelen(priv->c);

  *(out++) = nl & 0xff;
  *(out++) = nl >> 8;
  rsa_mpz_export(out, NULL, pub->n);
  out += rsa_mpz_bytelen(pub->n);

  *(out++) = el & 0xff;
  *(out++) = el >> 8;
  rsa_mpz_export(out, NULL, pub->e);
  out += rsa_mpz_bytelen(pub->e);

  *(out++) = dl & 0xff;
  *(out++) = dl >> 8;
  rsa_mpz_export(out, NULL, priv->d);
  out += rsa_mpz_bytelen(priv->d);

  *(out++) = pl & 0xff;
  *(out++) = pl >> 8;
  rsa_mpz_export(out, NULL, priv->p);
  out += rsa_mpz_bytelen(priv->p);

  *(out++) = ql & 0xff;
  *(out++) = ql >> 8;
  rsa_mpz_export(out, NULL, priv->q);
  out += rsa_mpz_bytelen(priv->q);

  *(out++) = dpl & 0xff;
  *(out++) = dpl >> 8;
  rsa_mpz_export(out, NULL, priv->a);
  out += rsa_mpz_bytelen(priv->a);

  *(out++) = dql & 0xff;
  *(out++) = dql >> 8;
  rsa_mpz_export(out, NULL, priv->b);
  out += rsa_mpz_bytelen(priv->b);

  *(out++) = qil & 0xff;
  *(out++) = qil >> 8;
  rsa_mpz_export(out, NULL, priv->c);
  out += rsa_mpz_bytelen(priv->c);
}

static void
bcrypto_rsa_pub2key(bcrypto_rsa_key_t *out, const struct rsa_public_key *pub) {
  size_t nl = rsa_mpz_bytelen(pub->n);
  size_t el = rsa_mpz_bytelen(pub->e);

  *(out++) = nl & 0xff;
  *(out++) = nl >> 8;
  rsa_mpz_export(out, NULL, pub->n);
  out += rsa_mpz_bytelen(pub->n);

  *(out++) = el & 0xff;
  *(out++) = el >> 8;
  rsa_mpz_export(out, NULL, pub->e);
  out += rsa_mpz_bytelen(pub->e);
}

#else

void
bcrypto_rsa_key_init(bcrypto_rsa_key_t *key) {
  memset((void *)key, 0x00, sizeof(bcrypto_rsa_key_t));
  key->slab = NULL;
}

void
bcrypto_rsa_key_uninit(bcrypto_rsa_key_t *key) {
  if (key->slab != NULL) {
    free(key->slab);
    key->slab = NULL;
  }
}

size_t
bcrypto_rsa_key_size(const bcrypto_rsa_key_t *key) {
  size_t i = 0;

  for (; i < key->nl; i++) {
    if (key->nd[i] != 0)
      break;
  }

  i = key->nl - i;

  if (i < BCRYPTO_RSA_MIN_BYTES || i > BCRYPTO_RSA_MAX_BYTES)
    return 0;

  return i;
}

static void
bcrypto_rsa_key2priv(struct rsa_private_key *out_priv,
                     struct rsa_public_key *out_pub,
                     const bcrypto_rsa_key_t *key) {
  rsa_mpz_import(out_pub->n, key->nd, key->nl);
  rsa_mpz_import(out_pub->e, key->ed, key->el);
  rsa_mpz_import(out_priv->d, key->dd, key->dl);
  rsa_mpz_import(out_priv->p, key->pd, key->pl);
  rsa_mpz_import(out_priv->q, key->qd, key->ql);
  rsa_mpz_import(out_priv->a, key->dpd, key->dpl);
  rsa_mpz_import(out_priv->b, key->dqd, key->dql);
  rsa_mpz_import(out_priv->c, key->qid, key->qil);
  out_priv->size = rsa_mpz_bytelen(out_pub->n);
  out_pub->size = out_priv->size;
}

static void
bcrypto_rsa_key2pub(struct rsa_public_key *out, const bcrypto_rsa_key_t *key) {
  rsa_mpz_import(out->n, key->nd, key->nl);
  rsa_mpz_import(out->e, key->ed, key->el);
  out->size = rsa_mpz_bytelen(out->n);
}

static void
bcrypto_rsa_priv2key(bcrypto_rsa_key_t *out,
                     const struct rsa_private_key *priv,
                     const struct rsa_public_key *pub) {
  uint8_t *slab = NULL;
  size_t nl = rsa_mpz_bytelen(pub->n);
  size_t el = rsa_mpz_bytelen(pub->e);
  size_t dl = rsa_mpz_bytelen(priv->d);
  size_t pl = rsa_mpz_bytelen(priv->p);
  size_t ql = rsa_mpz_bytelen(priv->q);
  size_t dpl = rsa_mpz_bytelen(priv->a);
  size_t dql = rsa_mpz_bytelen(priv->b);
  size_t qil = rsa_mpz_bytelen(priv->c);
  size_t size = nl + el + dl + pl + ql + dpl + dql + qil;
  size_t pos = 0;

  /* Align. */
  if (size & 7)
    size += 8 - (size & 7);

  slab = (uint8_t *)malloc(size);
  assert(slab != NULL);

  out->slab = slab;

  out->nd = (uint8_t *)&slab[pos];
  out->nl = nl;
  pos += nl;

  out->ed = (uint8_t *)&slab[pos];
  out->el = el;
  pos += el;

  out->dd = (uint8_t *)&slab[pos];
  out->dl = dl;
  pos += dl;

  out->pd = (uint8_t *)&slab[pos];
  out->pl = pl;
  pos += pl;

  out->qd = (uint8_t *)&slab[pos];
  out->ql = ql;
  pos += ql;

  out->dpd = (uint8_t *)&slab[pos];
  out->dpl = dpl;
  pos += dpl;

  out->dqd = (uint8_t *)&slab[pos];
  out->dql = dql;
  pos += dql;

  out->qid = (uint8_t *)&slab[pos];
  out->qil = qil;
  pos += qil;

  rsa_mpz_export(out->nd, NULL, pub->n);
  rsa_mpz_export(out->ed, NULL, pub->e);
  rsa_mpz_export(out->dd, NULL, priv->d);
  rsa_mpz_export(out->pd, NULL, priv->p);
  rsa_mpz_export(out->qd, NULL, priv->q);
  rsa_mpz_export(out->dpd, NULL, priv->a);
  rsa_mpz_export(out->dqd, NULL, priv->b);
  rsa_mpz_export(out->qid, NULL, priv->c);
}

static void
bcrypto_rsa_pub2key(bcrypto_rsa_key_t *out, const struct rsa_public_key *pub) {
  uint8_t *slab = NULL;
  size_t nl = rsa_mpz_bytelen(pub->n);
  size_t el = rsa_mpz_bytelen(pub->e);
  size_t size = nl + el;
  size_t pos = 0;

  /* Align. */
  if (size & 7)
    size += 8 - (size & 7);

  slab = (uint8_t *)malloc(size);
  assert(slab != NULL);

  out->slab = slab;

  out->nd = (uint8_t *)&slab[pos];
  out->nl = nl;
  pos += nl;

  out->ed = (uint8_t *)&slab[pos];
  out->el = el;
  pos += el;

  rsa_mpz_export(out->nd, NULL, pub->n);
  rsa_mpz_export(out->ed, NULL, pub->e);
}
#endif

static size_t
bcrypto_rsa_mod_size(const struct rsa_public_key *pub) {
  return rsa_mpz_bytelen(pub->n);
}

static size_t
bcrypto_rsa_mod_bits(const struct rsa_public_key *pub) {
  return rsa_mpz_bitlen(pub->n);
}

int
bcrypto_rsa_privkey_generate(bcrypto_rsa_key_t *out, int bits,
                             uint64_t exponent) {
  struct rsa_public_key pub;
  struct rsa_private_key priv;
  int result = 0;

  if (bits < BCRYPTO_RSA_MIN_BITS || bits > BCRYPTO_RSA_MAX_BITS)
    return 0;

  if (exponent < BCRYPTO_RSA_MIN_EXP || exponent > BCRYPTO_RSA_MAX_EXP)
    return 0;

  if ((exponent & 1ull) == 0ull)
    return 0;

  rsa_public_key_init(&pub);
  rsa_private_key_init(&priv);

  mpz_set_ui(pub.e, exponent);

  if (!rsa_generate_keypair(&pub, &priv, NULL,
                            (nettle_random_func *)bcrypto_rng,
                            NULL, NULL, bits, 0)) {
    goto fail;
  }

  bcrypto_rsa_priv2key(out, &priv, &pub);

  result = 1;
fail:
  rsa_public_key_clear(&pub);
  rsa_private_key_clear(&priv);
  return result;
}

int
bcrypto_rsa_privkey_compute(bcrypto_rsa_key_t *out,
                            const bcrypto_rsa_key_t *key) {
  struct rsa_public_key pub;
  struct rsa_private_key priv;
  mpz_t r0, r1, r2;
  int result = 0;

  rsa_public_key_init(&pub);
  rsa_private_key_init(&priv);

  bcrypto_rsa_key2priv(&priv, &pub, key);

  if (!bcrypto_rsa_sane_compute(&priv, &pub))
    goto fail;

  if (!bcrypto_rsa_needs_compute(&priv, &pub)) {
    rsa_public_key_clear(&pub);
    rsa_private_key_clear(&priv);
    return 2;
  }

  mpz_init(r0);
  mpz_init(r1);
  mpz_init(r2);

  /* See: https://github.com/openssl/openssl/blob/82eba37/crypto/rsa/rsa_gen.c */
  /* modulus n = p * q * r_3 * r_4 */
  if (mpz_sgn(pub.n) == 0)
    mpz_mul(pub.n, priv.p, priv.q);

  /* p - 1 */
  mpz_sub_ui(r1, priv.p, 1);

  /* q - 1 */
  mpz_sub_ui(r2, priv.q, 1);

  /* (p - 1)(q - 1) */
  mpz_mul(r0, r1, r2);

  if (mpz_sgn(pub.e) == 0) {
    if (mpz_invert(pub.e, priv.d, r0) == 0)
      goto fail;
  }

  if (mpz_sgn(priv.d) == 0) {
    if (mpz_invert(priv.d, pub.e, r0) == 0)
      goto fail;
  }

  /* calculate d mod (p-1) and d mod (q - 1) */
  if (mpz_sgn(priv.a) == 0)
    mpz_mod(priv.a, priv.d, r1);

  if (mpz_sgn(priv.b) == 0)
    mpz_mod(priv.b, priv.d, r2);

  /* calculate inverse of q mod p */
  if (mpz_sgn(priv.c) == 0) {
    if (mpz_invert(priv.c, priv.q, priv.p) == 0)
      goto fail;
  }

  bcrypto_rsa_priv2key(out, &priv, &pub);
  result = 1;
fail:
  mpz_clear(r0);
  mpz_clear(r1);
  mpz_clear(r2);
  return result;
}

int
bcrypto_rsa_privkey_verify(const bcrypto_rsa_key_t *key) {
  struct rsa_public_key pub;
  struct rsa_private_key priv;
  int result = 0;

  rsa_public_key_init(&pub);
  rsa_private_key_init(&priv);

  bcrypto_rsa_key2priv(&priv, &pub, key);

  if (!bcrypto_rsa_sane_privkey(&priv, &pub))
    goto fail;

  if (!rsa_public_key_prepare(&pub))
    goto fail;

  if (!rsa_private_key_prepare(&priv))
    goto fail;

  result = 1;
fail:
  rsa_public_key_clear(&pub);
  rsa_private_key_clear(&priv);
  return result;
}

int
bcrypto_rsa_pubkey_verify(const bcrypto_rsa_key_t *key) {
  struct rsa_public_key pub;
  rsa_public_key_init(&pub);
  bcrypto_rsa_key2pub(&pub, key);
  int result = bcrypto_rsa_sane_pubkey(&pub);
  rsa_public_key_clear(&pub);
  return result;
}

int
bcrypto_rsa_sign(uint8_t *out,
                 int type,
                 const uint8_t *msg,
                 size_t msg_len,
                 const bcrypto_rsa_key_t *key) {
  struct rsa_public_key pub;
  struct rsa_private_key priv;
  mpz_t s;
  int result = 0;

  rsa_public_key_init(&pub);
  rsa_private_key_init(&priv);
  mpz_init(s);

  if (type < BCRYPTO_HASH_MIN || type > BCRYPTO_HASH_MAX)
    goto fail;

  if (msg == NULL || msg_len != bcrypto_hash_size(type))
    goto fail;

  bcrypto_rsa_key2priv(&priv, &pub, key);

  if (!bcrypto_rsa_sane_privkey(&priv, &pub))
    goto fail;

  uint8_t *entry = (uint8_t *)PKCS1_PREFIXES[type];
  size_t prefix_size = (size_t)entry[0];
  uint8_t info[BCRYPTO_RSA_MAX_PREFIX + BCRYPTO_HASH_MAX_SIZE];
  size_t info_len = prefix_size + msg_len;

  memcpy(&info[0], &entry[1], prefix_size);
  memcpy(&info[prefix_size], msg, msg_len);

  if (!rsa_pkcs1_sign_tr(&pub, &priv, NULL,
                         (nettle_random_func *)bcrypto_rng,
                         info_len, info, s)) {
    goto fail;
  }

  rsa_mpz_pad(out, pub.size, s);

  result = 1;
fail:
  rsa_public_key_clear(&pub);
  rsa_private_key_clear(&priv);
  mpz_clear(s);
  return result;
}

int
bcrypto_rsa_verify(int type,
                   const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *sig,
                   size_t sig_len,
                   const bcrypto_rsa_key_t *key) {
  struct rsa_public_key pub;
  mpz_t s;
  int result = 0;

  rsa_public_key_init(&pub);
  mpz_init(s);

  if (type < BCRYPTO_HASH_MIN || type > BCRYPTO_HASH_MAX)
    goto fail;

  if (msg == NULL || msg_len != bcrypto_hash_size(type))
    goto fail;

  bcrypto_rsa_key2pub(&pub, key);

  if (sig == NULL || sig_len != bcrypto_rsa_mod_size(&pub))
    goto fail;

  if (!bcrypto_rsa_sane_pubkey(&pub))
    goto fail;

  rsa_mpz_import(s, sig, sig_len);

  uint8_t *entry = (uint8_t *)PKCS1_PREFIXES[type];
  size_t prefix_size = (size_t)entry[0];
  uint8_t info[BCRYPTO_RSA_MAX_PREFIX + BCRYPTO_HASH_MAX_SIZE];
  size_t info_len = prefix_size + msg_len;

  memcpy(&info[0], &entry[1], prefix_size);
  memcpy(&info[prefix_size], msg, msg_len);

  if (!rsa_pkcs1_verify(&pub, info_len, info, s))
    goto fail;

  result = 1;
fail:
  rsa_public_key_clear(&pub);
  mpz_clear(s);
  return result;
}

int
bcrypto_rsa_encrypt(uint8_t *out,
                    const uint8_t *pt,
                    size_t pt_len,
                    const bcrypto_rsa_key_t *key) {
  int result = 0;
  struct rsa_public_key pub;
  mpz_t c;

  rsa_public_key_init(&pub);
  mpz_init(c);

  bcrypto_rsa_key2pub(&pub, key);

  if (!bcrypto_rsa_sane_pubkey(&pub))
    goto fail;

  if (!rsa_encrypt(&pub, NULL,
                   (nettle_random_func *)bcrypto_rng,
                   pt_len, pt, c)) {
    goto fail;
  }

  rsa_mpz_pad(out, pub.size, c);

  result = 1;
fail:
  rsa_public_key_clear(&pub);
  mpz_clear(c);
  return result;
}

int
bcrypto_rsa_decrypt(uint8_t *out,
                    size_t *out_len,
                    const uint8_t *ct,
                    size_t ct_len,
                    const bcrypto_rsa_key_t *key) {
  int result = 0;
  struct rsa_public_key pub;
  struct rsa_private_key priv;
  mpz_t gib;

  rsa_public_key_init(&pub);
  rsa_private_key_init(&priv);
  mpz_init(gib);

  bcrypto_rsa_key2priv(&priv, &pub, key);
  rsa_mpz_import(gib, ct, ct_len);

  if (!bcrypto_rsa_sane_privkey(&priv, &pub))
    goto fail;

  if (!rsa_decrypt_tr(&pub, &priv, NULL,
                      (nettle_random_func *)bcrypto_rng,
                      out_len, out, gib)) {
    goto fail;
  }

  result = 1;
fail:
  rsa_public_key_clear(&pub);
  rsa_private_key_clear(&priv);
  mpz_clear(gib);
  return result;
}

static void
mgf1xor(const struct nettle_hash *hash, void *state,
        const uint8_t *seed, size_t seed_len,
        uint8_t *out, size_t out_len) {
  uint8_t counter[4];
  uint8_t digest[BCRYPTO_HASH_MAX_SIZE];

  memset(&counter[0], 0x00, 4);

  size_t done = 0;

  while (done < out_len) {
    hash->init(state);
    hash->update(state, seed_len, seed);
    hash->update(state, 4, counter);
    hash->digest(state, hash->digest_size, digest);

    for (size_t i = 0; i < hash->digest_size && done < out_len; i++) {
      out[done] ^= digest[i];
      done += 1;
    }

    for (int i = 3; i >= 0; i--) {
      counter[i] += 1;

      if (counter[i] != 0x00)
        break;
    }
  }
}

static inline unsigned int
safe_equal_int(unsigned int x, unsigned int y) {
  return ((x ^ y) - 1) >> 31;
}

static inline unsigned int
safe_select(unsigned int v, unsigned int x, unsigned int y) {
  return (~(v - 1) & x) | ((v - 1) & y);
}

static inline unsigned int
safe_equal(const uint8_t *x, const uint8_t *y, size_t len) {
  unsigned int v = 0;

  for (size_t i = 0; i < len; i++)
    v |= x[i] ^ y[i];

  return safe_equal_int(v, 0);
}

int
bcrypto_rsa_encrypt_oaep(uint8_t *out,
                         int type,
                         const uint8_t *pt,
                         size_t pt_len,
                         const bcrypto_rsa_key_t *key,
                         const uint8_t *label,
                         size_t label_len) {
  int result = 0;
  struct rsa_public_key pub;

  rsa_public_key_init(&pub);

  const struct nettle_hash *hash = bcrypto_hash_get(type);

  if (hash == NULL)
    goto fail;

  bcrypto_rsa_key2pub(&pub, key);

  if (!bcrypto_rsa_sane_pubkey(&pub))
    goto fail;

  const uint8_t *msg = pt;
  size_t klen = pub.size;
  size_t mlen = pt_len;
  size_t hlen = hash->digest_size;

  if (mlen > klen - 2 * hlen - 2)
    goto fail;

  // EM = 0x00 || mgf1(SEED) || mgf1(DB)
  uint8_t *em = out;
  uint8_t *seed = &em[1];
  size_t slen = hlen;
  uint8_t *db = &em[1 + hlen];
  size_t dlen = klen - (1 + hlen);

  em[0] = 0x00;

  // SEED = Random Bytes
  if (!bcrypto_random(&seed[0], slen))
    goto fail;

  uint8_t state[BCRYPTO_HASH_MAX_CONTEXT_SIZE];

  // DB = HASH(LABEL) || PS || 0x01 || M
  hash->init(state);
  hash->update(state, label_len, label);
  hash->digest(state, hlen, &db[0]);

  memset(&db[hlen], 0x00, dlen - hlen);
  db[dlen - mlen - 1] = 0x01;
  memcpy(&db[dlen - mlen], msg, mlen);

  mgf1xor(hash, state, seed, slen, db, dlen);
  mgf1xor(hash, state, db, dlen, seed, slen);

  result = bcrypto_rsa_encrypt_raw(out, em, klen, key);
fail:
  rsa_public_key_clear(&pub);
  return result;
}

int
bcrypto_rsa_decrypt_oaep(uint8_t *out,
                         size_t *out_len,
                         int type,
                         const uint8_t *ct,
                         size_t ct_len,
                         const bcrypto_rsa_key_t *key,
                         const uint8_t *label,
                         size_t label_len) {
  int result = 0;
  struct rsa_public_key pub;
  struct rsa_private_key priv;

  rsa_public_key_init(&pub);
  rsa_private_key_init(&priv);

  const struct nettle_hash *hash = bcrypto_hash_get(type);

  if (hash == NULL)
    goto fail;

  bcrypto_rsa_key2priv(&priv, &pub, key);

  if (!bcrypto_rsa_sane_privkey(&priv, &pub))
    goto fail;

  if (ct == NULL || ct_len != pub.size)
    goto fail;

  size_t klen = pub.size;
  size_t hlen = hash->digest_size;

  uint8_t *em = out;

  if (!bcrypto_rsa_decrypt_raw(em, ct, ct_len, key))
    goto fail;

  uint8_t expect[BCRYPTO_HASH_MAX_SIZE];
  uint8_t state[BCRYPTO_HASH_MAX_CONTEXT_SIZE];

  hash->init(state);
  hash->update(state, label_len, label);
  hash->digest(state, hlen, expect);

  unsigned int fbiz = safe_equal_int(em[0], 0x00);
  uint8_t *seed = &em[1];
  size_t slen = hlen;
  uint8_t *db = &em[hlen + 1];
  size_t dlen = klen - (1 + hlen);

  mgf1xor(hash, state, db, dlen, seed, slen);
  mgf1xor(hash, state, seed, slen, db, dlen);

  uint8_t *lhash = &db[0];
  unsigned int lvalid = safe_equal(lhash, expect, hlen);

  unsigned int looking = 1;
  unsigned int index = 0;
  unsigned int invalid = 0;

  uint8_t *rest = &db[hlen];
  size_t rlen = dlen - hlen;

  for (size_t i = 0; i < rlen; i++) {
    unsigned int equals0 = safe_equal_int(rest[i], 0x00);
    unsigned int equals1 = safe_equal_int(rest[i], 0x01);

    index = safe_select(looking & equals1, i, index);
    looking = safe_select(equals1, 0, looking);
    invalid = safe_select(looking & ~equals0, 1, invalid);
  }

  if ((fbiz & lvalid & ~invalid & ~looking) != 1)
    goto fail;

  *out_len = rlen - (index + 1);
  memmove(&out[0], &rest[index + 1], *out_len);
  result = 1;
fail:
  rsa_public_key_clear(&pub);
  rsa_private_key_clear(&priv);
  return result;
}

static int
_rsa_pss_sign_digest_tr(int type, const struct rsa_public_key *pub,
                        const struct rsa_private_key *key,
                        void *random_ctx, nettle_random_func *random,
                        size_t salt_length, const uint8_t *salt,
                        const uint8_t *digest,
                        mpz_t s) {
  mpz_t m;
  int res;

  mpz_init(m);

  res = pss_encode_mgf1(m, mpz_sizeinbase(pub->n, 2) - 1,
                        bcrypto_hash_get(type),
                        salt_length,
                        salt, digest);

  if (res)
    res = rsa_compute_root_tr(pub, key, random_ctx, random, s, m);

  mpz_clear(m);

  return res;
}

int
bcrypto_rsa_sign_pss(uint8_t *out,
                     int type,
                     const uint8_t *msg,
                     size_t msg_len,
                     const bcrypto_rsa_key_t *key,
                     int salt_len) {
  int result = 0;
  struct rsa_public_key pub;
  struct rsa_private_key priv;
  mpz_t s;
  uint8_t salt[BCRYPTO_RSA_MAX_BYTES];

  rsa_public_key_init(&pub);
  rsa_private_key_init(&priv);
  mpz_init(s);

  if (!bcrypto_rsa_has_hash(type))
    goto fail;

  if (msg == NULL || msg_len != bcrypto_hash_size(type))
    goto fail;

  bcrypto_rsa_key2priv(&priv, &pub, key);

  if (!bcrypto_rsa_sane_privkey(&priv, &pub))
    goto fail;

  if (salt_len == 0) // Auto
    salt_len = rsa_mpz_bytelen(pub.n) - 2 - msg_len;
  else if (salt_len == -1) // Equals
    salt_len = msg_len;

  if (!bcrypto_random(&salt[0], salt_len))
    goto fail;

  if (!_rsa_pss_sign_digest_tr(type, &pub, &priv, NULL,
                               (nettle_random_func *)bcrypto_rng,
                               (size_t)salt_len, salt, msg, s)) {
    goto fail;
  }

  rsa_mpz_pad(out, pub.size, s);

  result = 1;
fail:
  rsa_public_key_clear(&pub);
  rsa_private_key_clear(&priv);
  mpz_clear(s);
  return result;
}

static int
_rsa_pss_verify_digest(int type,
                       const struct rsa_public_key *key,
                       size_t salt_length,
                       const uint8_t *digest,
                       const mpz_t signature) {
  int res;
  mpz_t m;

  mpz_init(m);

  res = _rsa_verify_recover(key, m, signature);

  if (res) {
    res = pss_verify_mgf1(m, mpz_sizeinbase(key->n, 2) - 1,
                          bcrypto_hash_get(type),
                          salt_length, digest);
  }

  mpz_clear(m);

  return res;
}

int
bcrypto_rsa_verify_pss(int type,
                       const uint8_t *msg,
                       size_t msg_len,
                       const uint8_t *sig,
                       size_t sig_len,
                       const bcrypto_rsa_key_t *key,
                       int salt_len) {
  int result = 0;
  struct rsa_public_key pub;
  mpz_t s;

  rsa_public_key_init(&pub);
  mpz_init(s);

  if (!bcrypto_rsa_has_hash(type))
    goto fail;

  if (msg == NULL || msg_len != bcrypto_hash_size(type))
    goto fail;

  bcrypto_rsa_key2pub(&pub, key);

  if (!bcrypto_rsa_sane_pubkey(&pub))
    goto fail;

  if (sig == NULL || sig_len != bcrypto_rsa_mod_size(&pub))
    goto fail;

  if (salt_len == 0)
    salt_len = (((rsa_mpz_bitlen(pub.n) - 1) + 7) >> 3) - (msg_len + 2);
  else if (salt_len == -1)
    salt_len = msg_len;

  rsa_mpz_import(s, sig, sig_len);

  if (!_rsa_pss_verify_digest(type, &pub, (size_t)salt_len, msg, s))
    goto fail;

  result = 1;
fail:
  rsa_public_key_clear(&pub);
  mpz_clear(s);
  return result;
}

int
bcrypto_rsa_encrypt_raw(uint8_t *out,
                        const uint8_t *pt,
                        size_t pt_len,
                        const bcrypto_rsa_key_t *key) {
  int result = 0;
  struct rsa_public_key pub;
  mpz_t m;

  rsa_public_key_init(&pub);
  mpz_init(m);

  bcrypto_rsa_key2pub(&pub, key);

  if (!bcrypto_rsa_sane_pubkey(&pub))
    goto fail;

  if (pt == NULL || pt_len != bcrypto_rsa_mod_size(&pub))
    goto fail;

  rsa_mpz_import(m, pt, pt_len);
  mpz_powm(m, m, pub.e, pub.n);

  rsa_mpz_pad(out, pub.size, m);

  result = 1;
fail:
  rsa_public_key_clear(&pub);
  mpz_clear(m);
  return result;
}

int
bcrypto_rsa_decrypt_raw(uint8_t *out,
                        const uint8_t *ct,
                        size_t ct_len,
                        const bcrypto_rsa_key_t *key) {
  int result = 0;
  struct rsa_public_key pub;
  struct rsa_private_key priv;
  mpz_t m, x;

  rsa_public_key_init(&pub);
  rsa_private_key_init(&priv);
  mpz_init(m);
  mpz_init(x);

  bcrypto_rsa_key2priv(&priv, &pub, key);

  if (!bcrypto_rsa_sane_privkey(&priv, &pub))
    goto fail;

  if (ct == NULL || ct_len != bcrypto_rsa_mod_size(&pub))
    goto fail;

  rsa_mpz_import(m, ct, ct_len);

  if (!rsa_compute_root_tr(&pub, &priv, NULL,
                           (nettle_random_func *)bcrypto_rng, x, m)) {
    goto fail;
  }

  rsa_mpz_pad(out, pub.size, x);

  result = 1;
fail:
  rsa_public_key_clear(&pub);
  rsa_private_key_clear(&priv);
  mpz_clear(m);
  mpz_clear(x);
  return result;
}

int
bcrypto_rsa_veil(uint8_t *out,
                 const uint8_t *ct,
                 size_t ct_len,
                 size_t bits,
                 const bcrypto_rsa_key_t *key) {
  int result = 0;
  struct rsa_public_key pub;
  mpz_t c0, ctlim, rlim, c1, cr, tmp;

  rsa_public_key_init(&pub);

  bcrypto_rsa_key2pub(&pub, key);

  if (!bcrypto_rsa_sane_pubkey(&pub))
    goto fail;

  mpz_init(c0);
  mpz_init(ctlim);
  mpz_init(rlim);
  mpz_init(c1);
  mpz_init(cr);
  mpz_init(tmp);

  if (ct == NULL || ct_len != bcrypto_rsa_mod_size(&pub))
    goto fail;

  /* Can't make ciphertext smaller. */
  if (bits < bcrypto_rsa_mod_bits(&pub))
    goto fail;

  rsa_mpz_import(c0, ct, ct_len);

  mpz_set_ui(ctlim, 0);
  mpz_set_ui(rlim, 0);
  mpz_set_ui(c1, 0);
  mpz_set_ui(cr, 0);

  /* Invalid ciphertext. */
  if (mpz_cmp(c0, pub.n) >= 0)
    goto fail;

  /* ctlim = 1 << (bits + 0) */
  mpz_set_ui(ctlim, 1);
  mpz_mul_2exp(ctlim, ctlim, bits);

  /* rlim = (ctlim - c0 + n - 1) / n */
  mpz_set(rlim, ctlim);
  mpz_sub(rlim, rlim, c0);
  mpz_add(rlim, rlim, pub.n);
  mpz_sub_ui(rlim, rlim, 1);
  mpz_tdiv_q(rlim, rlim, pub.n);

  /* c1 = ctlim */
  mpz_set(c1, ctlim);

  /* while c1 >= ctlim */
  while (mpz_cmp(c1, ctlim) >= 0) {
    /* cr = random_int(rlim) */
    nettle_mpz_random(cr, NULL, bcrypto_rng, rlim);

    if (mpz_cmp_ui(rlim, 1) > 0 && mpz_sgn(cr) == 0)
      continue;

    /* c1 = c0 + cr * n */
    mpz_mul(cr, cr, pub.n);
    mpz_add(c1, c0, cr);
  }

  mpz_mod(cr, c1, pub.n);

  assert(mpz_cmp(cr, c0) == 0);
  assert((size_t)rsa_mpz_bitlen(c1) <= bits);

  rsa_mpz_pad(out, (bits + 7) / 8, c1);

  result = 1;
fail:
  rsa_public_key_clear(&pub);
  mpz_clear(c0);
  mpz_clear(ctlim);
  mpz_clear(rlim);
  mpz_clear(c1);
  mpz_clear(cr);
  mpz_clear(tmp);
  return result;
}

int
bcrypto_rsa_unveil(uint8_t *out,
                   const uint8_t *veiled,
                   size_t veiled_len,
                   size_t bits,
                   const bcrypto_rsa_key_t *key) {
  int result = 0;
  struct rsa_public_key pub;
  mpz_t c1;

  rsa_public_key_init(&pub);
  mpz_init(c1);

  bcrypto_rsa_key2pub(&pub, key);

  if (!bcrypto_rsa_sane_pubkey(&pub))
    goto fail;

  if (veiled == NULL || veiled_len < pub.size)
    goto fail;

  rsa_mpz_import(c1, veiled, veiled_len);

  if (rsa_mpz_bitlen(c1) > bits)
    goto fail;

  /* c0 = c1 % n */
  mpz_mod(c1, c1, pub.n);

  assert((size_t)rsa_mpz_bytelen(c1) <= pub.size);

  rsa_mpz_pad(out, pub.size, c1);

  result = 1;
fail:
  rsa_public_key_clear(&pub);
  mpz_clear(c1);
  return result;
}

int
bcrypto_rsa_has_hash(int type) {
  return bcrypto_hash_get(type) != NULL;
}
