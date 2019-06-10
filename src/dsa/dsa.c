#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include <stdlib.h>
#include "dsa.h"

#include "../random/random.h"

static inline size_t
dsa_mpz_bitlen(const mpz_t n) {
  if (mpz_sgn(n) == 0)
    return 0;

  return mpz_sizeinbase(n, 2);
}

#define dsa_mpz_bytelen(n) \
  (dsa_mpz_bitlen((n)) + 7) / 8

#define dsa_mpz_import(ret, data, len) \
  mpz_import((ret), (len), 1, sizeof((data)[0]), 0, 0, (data))

#define dsa_mpz_export(data, size, n) \
  mpz_export((data), (size), 1, sizeof((data)[0]), 0, 0, (n));

static inline void
dsa_mpz_pad(void *out, size_t size, const mpz_t n) {
  size_t len = dsa_mpz_bytelen(n);

  assert(len <= size);

  size_t pos = size - len;

  memset(out, 0x00, pos);

  dsa_mpz_export(out + pos, NULL, n);
}

static int
bcrypto_dsa_sane_params(const struct dsa_params *params) {
  size_t pb = dsa_mpz_bitlen(params->p);
  size_t qb = dsa_mpz_bitlen(params->q);
  size_t gb = dsa_mpz_bitlen(params->g);

  if (pb < BCRYPTO_DSA_MIN_BITS || pb > BCRYPTO_DSA_MAX_BITS)
    return 0;

  if (qb != 160 && qb != 224 && qb != 256)
    return 0;

  if (gb < 2 || gb > pb)
    return 0;

  if (mpz_even_p(params->p))
    return 0;

  if (mpz_even_p(params->q))
    return 0;

  if (mpz_cmp(params->g, params->p) >= 0)
    return 0;

  return 1;
}

static int
bcrypto_dsa_sane_pubkey(const struct dsa_params *params, const mpz_t y) {
  if (!bcrypto_dsa_sane_params(params))
    return 0;

  size_t pb = dsa_mpz_bitlen(params->p);
  size_t yb = dsa_mpz_bitlen(y);

  if (yb == 0 || yb > pb)
    return 0;

  if (mpz_cmp(y, params->p) >= 0)
    return 0;

  return 1;
}

static int
bcrypto_dsa_sane_privkey(const struct dsa_params *params,
                         const mpz_t y, const mpz_t x) {
  if (!bcrypto_dsa_sane_pubkey(params, y))
    return 0;

  size_t qb = dsa_mpz_bitlen(params->q);
  size_t xb = dsa_mpz_bitlen(x);

  if (xb == 0 || xb > qb)
    return 0;

  if (mpz_cmp(x, params->q) >= 0)
    return 0;

  return 1;
}

static int
bcrypto_dsa_sane_compute(const struct dsa_params *params,
                         const mpz_t y, const mpz_t x) {
  size_t pb = dsa_mpz_bitlen(params->p);
  size_t qb = dsa_mpz_bitlen(params->q);
  size_t gb = dsa_mpz_bitlen(params->g);
  size_t yb = dsa_mpz_bitlen(y);
  size_t xb = dsa_mpz_bitlen(x);

  if (pb < BCRYPTO_DSA_MIN_BITS || pb > BCRYPTO_DSA_MAX_BITS)
    return 0;

  if (qb != 160 && qb != 224 && qb != 256)
    return 0;

  if (gb < 2 || gb > pb)
    return 0;

  if (mpz_even_p(params->p))
    return 0;

  if (mpz_even_p(params->q))
    return 0;

  if (yb > pb)
    return 0;

  if (xb == 0 || xb > qb)
    return 0;

  if (mpz_cmp(params->g, params->p) >= 0)
    return 0;

  if (mpz_cmp(y, params->p) >= 0)
    return 0;

  if (mpz_cmp(x, params->q) >= 0)
    return 0;

  return 1;
}

static int
bcrypto_dsa_needs_compute(const struct dsa_params *params, const mpz_t y) {
  return dsa_mpz_bitlen(y) == 0;
}

#ifdef BCRYPTO_WASM

#define READINT(n, p) do {                \
  size = ((size_t)(p)[1] << 16) | (p)[0]; \
  dsa_mpz_import((n), (p) + 2, size);     \
  (p) += 2 + size;                        \
} while (0)                               \

static void
bcrypto_dsa_key2dsa(struct dsa_params *out,
                    mpz_t y, mpz_t x,
                    const bcrypto_dsa_key_t *key,
                    int mode) {
  size_t size = 0;
  const uint8_t *p = key;

  READINT(out->p, p);
  READINT(out->q, p);
  READINT(out->g, p);

  if (mode == 1 || mode == 2)
    READINT(y, p);

  if (mode == 2)
    READINT(x, p);
}

static void
bcrypto_dsa_dsa2key(bcrypto_dsa_key_t *out,
                    const struct dsa_params *params,
                    const mpz_t y, const mpz_t x,
                    int mode) {
  size_t pl = dsa_mpz_bytelen(params->p);
  size_t ql = dsa_mpz_bytelen(params->q);
  size_t gl = dsa_mpz_bytelen(params->g);
  size_t yl = 0;
  size_t xl = 0;

  if (mode == 1 || mode == 2)
    yl = dsa_mpz_bytelen(y);

  if (mode == 2)
    xl = dsa_mpz_bytelen(x);

  *(out++) = pl & 0xff;
  *(out++) = pl >> 8;
  dsa_mpz_export(out, NULL, params->p);
  out += dsa_mpz_bytelen(params->p);

  *(out++) = ql & 0xff;
  *(out++) = ql >> 8;
  dsa_mpz_export(out, NULL, params->q);
  out += dsa_mpz_bytelen(params->q);

  *(out++) = gl & 0xff;
  *(out++) = gl >> 8;
  dsa_mpz_export(out, NULL, params->g);
  out += dsa_mpz_bytelen(params->g);

  if (mode == 1 || mode == 2) {
    *(out++) = yl & 0xff;
    *(out++) = yl >> 8;
    dsa_mpz_export(out, NULL, y);
    out += dsa_mpz_bytelen(y);
  }

  if (mode == 2) {
    *(out++) = xl & 0xff;
    *(out++) = xl >> 8;
    dsa_mpz_export(out, NULL, x);
    out += dsa_mpz_bytelen(x);
  }
}

#else

static void
bcrypto_dsa_key2dsa(struct dsa_params *out,
                    mpz_t y, mpz_t x,
                    const bcrypto_dsa_key_t *key,
                    int mode) {
  dsa_mpz_import(out->p, key->pd, key->pl);
  dsa_mpz_import(out->q, key->qd, key->ql);
  dsa_mpz_import(out->g, key->gd, key->gl);

  if (mode == 1 || mode == 2)
    dsa_mpz_import(y, key->yd, key->yl);

  if (mode == 2)
    dsa_mpz_import(x, key->xd, key->xl);
}

static void
bcrypto_dsa_dsa2key(bcrypto_dsa_key_t *out,
                    const struct dsa_params *params,
                    const mpz_t y, const mpz_t x,
                    int mode) {
  uint8_t *slab = NULL;
  size_t pl = dsa_mpz_bytelen(params->p);
  size_t ql = dsa_mpz_bytelen(params->q);
  size_t gl = dsa_mpz_bytelen(params->g);
  size_t yl = 0;
  size_t xl = 0;

  if (mode == 1 || mode == 2)
    yl = dsa_mpz_bytelen(y);

  if (mode == 2)
    xl = dsa_mpz_bytelen(x);

  size_t size = pl + ql + gl + yl + xl;
  size_t pos = 0;

  /* Align. */
  if (size & 7)
    size += 8 - (size & 7);

  slab = (uint8_t *)malloc(size);
  assert(slab != NULL);

  out->slab = slab;

  out->pd = (uint8_t *)&slab[pos];
  out->pl = pl;
  pos += pl;

  out->qd = (uint8_t *)&slab[pos];
  out->ql = ql;
  pos += ql;

  out->gd = (uint8_t *)&slab[pos];
  out->gl = gl;
  pos += gl;

  if (mode == 1 || mode == 2) {
    out->yd = (uint8_t *)&slab[pos];
    out->yl = yl;
    pos += yl;
  }

  if (mode == 2) {
    out->xd = (uint8_t *)&slab[pos];
    out->xl = xl;
    pos += xl;
  }

  dsa_mpz_export(out->pd, NULL, params->p);
  dsa_mpz_export(out->qd, NULL, params->q);
  dsa_mpz_export(out->gd, NULL, params->g);

  if (mode == 1 || mode == 2)
    dsa_mpz_export(out->yd, NULL, y);

  if (mode == 2)
    dsa_mpz_export(out->xd, NULL, x);
}

static size_t
bcrypto_count_bytes(const uint8_t *data, size_t len) {
  size_t i = 0;

  for (; i < len; i++) {
    if (data[i] != 0)
      break;
  }

  return len - i;
}

void
bcrypto_dsa_key_init(bcrypto_dsa_key_t *key) {
  memset((void *)key, 0x00, sizeof(bcrypto_dsa_key_t));
  key->slab = NULL;
}

void
bcrypto_dsa_key_uninit(bcrypto_dsa_key_t *key) {
  if (key->slab != NULL) {
    free(key->slab);
    key->slab = NULL;
  }
}

size_t
bcrypto_dsa_key_psize(const bcrypto_dsa_key_t *key) {
  size_t size = bcrypto_count_bytes(key->pd, key->pl);

  if (size < BCRYPTO_DSA_MIN_FIELD_SIZE || size > BCRYPTO_DSA_MAX_FIELD_SIZE)
    return 0;

  return size;
}

size_t
bcrypto_dsa_key_qsize(const bcrypto_dsa_key_t *key) {
  size_t size = bcrypto_count_bytes(key->qd, key->ql);

  if (size < BCRYPTO_DSA_MIN_SCALAR_SIZE || size > BCRYPTO_DSA_MAX_SCALAR_SIZE)
    return 0;

  return size;
}

size_t
bcrypto_dsa_sig_size(const bcrypto_dsa_key_t *key) {
  return bcrypto_dsa_key_qsize(key) * 2;
}

size_t
bcrypto_dsa_der_size(const bcrypto_dsa_key_t *key) {
  return 9 + bcrypto_dsa_key_qsize(key) * 2;
}

#endif

static void
bcrypto_dsa_key2params(struct dsa_params *out, const bcrypto_dsa_key_t *key) {
  mpz_t y, x; /* unused */
  return bcrypto_dsa_key2dsa(out, y, x, key, 0);
}

static void
bcrypto_dsa_key2pub(struct dsa_params *out, mpz_t y,
                    const bcrypto_dsa_key_t *key) {
  mpz_t x; /* unused */
  return bcrypto_dsa_key2dsa(out, y, x, key, 1);
}

static void
bcrypto_dsa_key2priv(struct dsa_params *out,
                     mpz_t y, mpz_t x,
                     const bcrypto_dsa_key_t *key) {
  return bcrypto_dsa_key2dsa(out, y, x, key, 2);
}

static void
bcrypto_dsa_params2key(bcrypto_dsa_key_t *out,
                       const struct dsa_params *params) {
  mpz_t y, x; /* unused */
  return bcrypto_dsa_dsa2key(out, params, y, x, 0);
}

static void
bcrypto_dsa_pub2key(bcrypto_dsa_key_t *out,
                    const struct dsa_params *params,
                    const mpz_t y) {
  mpz_t x; /* unused */
  return bcrypto_dsa_dsa2key(out, params, y, x, 1);
}

static void
bcrypto_dsa_priv2key(bcrypto_dsa_key_t *out,
                     const struct dsa_params *params,
                     const mpz_t y, const mpz_t x) {
  return bcrypto_dsa_dsa2key(out, params, y, x, 2);
}

void
bcrypto_dsa_rs2sig(struct dsa_signature *out,
                   const uint8_t *sig, size_t qsize) {
  dsa_mpz_import(out->r, &sig[0], qsize);
  dsa_mpz_import(out->s, &sig[qsize], qsize);
}

void
bcrypto_dsa_sig2rs(uint8_t *out,
                   const struct dsa_signature *sig,
                   size_t qsize) {
  dsa_mpz_pad(&out[0], qsize, sig->r);
  dsa_mpz_pad(&out[qsize], qsize, sig->s);
}

int
bcrypto_dsa_der2sig(struct dsa_signature *out,
                    const uint8_t *raw, size_t raw_len,
                    size_t qsize) {
  size_t rpos, rlen, spos, slen;
  size_t pos = 0;
  size_t lenbyte;
  int overflow = 0;

  mpz_set_ui(out->r, 0);
  mpz_set_ui(out->s, 0);

  /* Sequence tag byte */
  if (pos == raw_len || raw[pos] != 0x30)
    return 0;

  pos++;

  /* Sequence length bytes */
  if (pos == raw_len)
    return 0;

  lenbyte = raw[pos++];

  if (lenbyte & 0x80) {
    lenbyte -= 0x80;

    if (pos + lenbyte > raw_len)
      return 0;

    pos += lenbyte;
  }

  /* Integer tag byte for R */
  if (pos == raw_len || raw[pos] != 0x02)
    return 0;

  pos++;

  /* Integer length for R */
  if (pos == raw_len)
    return 0;

  lenbyte = raw[pos++];

  if (lenbyte & 0x80) {
    lenbyte -= 0x80;

    if (pos + lenbyte > raw_len)
      return 0;

    while (lenbyte > 0 && raw[pos] == 0) {
      pos++;
      lenbyte--;
    }

    if (lenbyte >= sizeof(size_t))
      return 0;

    rlen = 0;

    while (lenbyte > 0) {
      rlen = (rlen << 8) + raw[pos];
      pos++;
      lenbyte--;
    }
  } else {
    rlen = lenbyte;
  }

  if (rlen > raw_len - pos)
    return 0;

  rpos = pos;
  pos += rlen;

  /* Integer tag byte for S */
  if (pos == raw_len || raw[pos] != 0x02)
    return 0;

  pos++;

  /* Integer length for S */
  if (pos == raw_len)
    return 0;

  lenbyte = raw[pos++];

  if (lenbyte & 0x80) {
    lenbyte -= 0x80;

    if (pos + lenbyte > raw_len)
      return 0;

    while (lenbyte > 0 && raw[pos] == 0) {
      pos++;
      lenbyte--;
    }

    if (lenbyte >= sizeof(size_t))
      return 0;

    slen = 0;

    while (lenbyte > 0) {
      slen = (slen << 8) + raw[pos];
      pos++;
      lenbyte--;
    }
  } else {
    slen = lenbyte;
  }

  if (slen > raw_len - pos)
    return 0;

  spos = pos;
  pos += slen;

  /* Ignore leading zeroes in R */
  while (rlen > 0 && raw[rpos] == 0) {
    rlen--;
    rpos++;
  }

  /* Copy R value */
  if (rlen > qsize)
    overflow = 1;
  else
    dsa_mpz_import(out->r, raw + rpos, rlen);

  /* Ignore leading zeroes in S */
  while (slen > 0 && raw[spos] == 0) {
    slen--;
    spos++;
  }

  /* Copy S value */
  if (slen > qsize)
    overflow = 1;
  else
    dsa_mpz_import(out->s, raw + spos, slen);

  if (overflow) {
    mpz_set_ui(out->r, 0);
    mpz_set_ui(out->s, 0);
  }

  return 1;
}

int
bcrypto_dsa_sig2der(uint8_t *out,
                    size_t *out_len,
                    const struct dsa_signature *sig,
                    size_t qsize) {
  size_t rlen = dsa_mpz_bytelen(sig->r);
  size_t slen = dsa_mpz_bytelen(sig->s);

  if (qsize >= 0x7d)
    return 0;

  if (rlen > qsize || slen > qsize)
    return 0;

  rlen += mpz_tstbit(sig->r, rlen * 8 - 1);
  slen += mpz_tstbit(sig->s, slen * 8 - 1);

  size_t seq = 2 + rlen + 2 + slen;
  size_t wide = seq >= 0x80 ? 1 : 0;
  size_t len = 2 + wide + seq;

  // if (len > *out_len)
  //   return 0;

  *(out++) = 0x30;

  if (wide)
    *(out++) = 0x81;

  *(out++) = seq;
  *(out++) = 0x02;
  *(out++) = rlen;

  dsa_mpz_pad(out, rlen, sig->r);
  out += rlen;

  *(out++) = 0x02;
  *(out++) = slen;

  dsa_mpz_pad(out, slen, sig->s);
  out += slen;

  *out_len = len;

  return 1;
}

int
bcrypto_dsa_params_generate(bcrypto_dsa_key_t *out, int bits) {
  int result = 0;
  struct dsa_params params;
  unsigned int qbits = bits < 2048 ? 160 : 256; /* OpenSSL behavior. */

  dsa_params_init(&params);

  if (bits < BCRYPTO_DSA_MIN_BITS || bits > BCRYPTO_DSA_MAX_BITS)
    goto fail;

  if (!dsa_generate_params(&params, NULL,
                           (nettle_random_func *)bcrypto_rng,
                           NULL, NULL, bits, qbits)) {
    goto fail;
  }

  bcrypto_dsa_params2key(out, &params);
  result = 1;
fail:
  dsa_params_clear(&params);
  return result;
}

int
bcrypto_dsa_params_verify(const bcrypto_dsa_key_t *key) {
  int result = 0;
  struct dsa_params params;
  mpz_t x;

  dsa_params_init(&params);
  mpz_init(x);

  bcrypto_dsa_key2params(&params, key);

  if (!bcrypto_dsa_sane_params(&params))
    goto fail;

  /* x = g^q mod p */
  mpz_powm(x, params.g, params.q, params.p);

  /* x != 1 */
  if (mpz_cmp_ui(x, 1) != 0)
    goto fail;

  result = 1;
fail:
  dsa_params_clear(&params);
  mpz_clear(x);
  return result;
}

int
bcrypto_dsa_params_export(uint8_t *out,
                          size_t *out_len,
                          const bcrypto_dsa_key_t *key) {
  return 0;
}

int
bcrypto_dsa_params_import(bcrypto_dsa_key_t *out,
                          const uint8_t *raw, size_t raw_len) {
  return 0;
}

int
bcrypto_dsa_privkey_create(bcrypto_dsa_key_t *out,
                           const bcrypto_dsa_key_t *key) {
  int result = 0;
  struct dsa_params params;
  mpz_t y, x;

  dsa_params_init(&params);
  mpz_init(y);
  mpz_init(x);

  bcrypto_dsa_key2params(&params, key);

  if (!bcrypto_dsa_sane_params(&params))
    goto fail;

  dsa_generate_keypair(&params, y, x, NULL, (nettle_random_func *)bcrypto_rng);

  bcrypto_dsa_priv2key(out, &params, y, x);
  result = 1;
fail:
  dsa_params_clear(&params);
  mpz_clear(y);
  mpz_clear(x);
  return result;
}

static void
dsa_pow_blind(mpz_t out,
              const mpz_t y, const mpz_t x,
              const mpz_t p, const mpz_t q) {
#ifdef BCRYPTO_HAS_GMP
  mpz_powm_sec(out, y, x, p);
#else
  /* Idea: exponentiate by scalar with a
     blinding factor, similar to how we
     blind multiplications in EC. */
  /* TODO: Optimize. */
  mpz_t tmp, blind, unblind, scalar, blinded;
  mpz_init(tmp);
  mpz_init(blind);
  mpz_init(unblind);
  mpz_init(scalar);
  mpz_init(blinded);

  /* blind := rand(1..q-1) */
  mpz_sub_ui(tmp, q, 1);
  nettle_mpz_random(blind, NULL, bcrypto_rng, tmp);
  mpz_add_ui(blind, blind, 1);
  mpz_add_ui(tmp, tmp, 1);

  /* unblind := y^(-blind mod q) mod p */
  mpz_sub(tmp, tmp, blind);
  mpz_powm(unblind, y, tmp, p);

  /* scalar := (x + blind) mod q */
  mpz_add(scalar, x, blind);
  mpz_mod(scalar, scalar, q);

  /* blinded := y^scalar mod p */
  mpz_powm(blinded, y, scalar, p);

  /* secret := (blinded * unblind) mod p */
  mpz_mul(out, blinded, unblind);
  mpz_mod(out, out, p);

  mpz_clear(tmp);
  mpz_clear(blind);
  mpz_clear(unblind);
  mpz_clear(scalar);
  mpz_clear(blinded);
#endif
}

int
bcrypto_dsa_privkey_compute(uint8_t *out,
                            size_t *out_len,
                            const bcrypto_dsa_key_t *key) {
  int result = 0;
  struct dsa_params params;
  mpz_t y, x;

  dsa_params_init(&params);
  mpz_init(y);
  mpz_init(x);

  bcrypto_dsa_key2priv(&params, y, x, key);

  if (!bcrypto_dsa_sane_compute(&params, y, x))
    goto fail;

  if (!bcrypto_dsa_needs_compute(&params, y)) {
    result = 2;
    goto fail;
  }

  /* y = g^x mod p */
  dsa_pow_blind(y, params.g, x, params.p, params.q);

  *out_len = dsa_mpz_bytelen(y);
  dsa_mpz_export(out, NULL, y);

  result = 1;
fail:
  dsa_params_clear(&params);
  mpz_clear(y);
  mpz_clear(x);
  return result;
}

int
bcrypto_dsa_privkey_verify(const bcrypto_dsa_key_t *key) {
  int result = 0;
  struct dsa_params params;
  mpz_t y, x, t;

  dsa_params_init(&params);
  mpz_init(y);
  mpz_init(x);
  mpz_init(t);

  bcrypto_dsa_key2priv(&params, y, x, key);

  if (!bcrypto_dsa_sane_privkey(&params, y, x))
    goto fail;

  /* t = g^q mod p */
  mpz_powm(t, params.g, params.q, params.p);

  /* t != 1 */
  if (mpz_cmp_ui(t, 1) != 0)
    goto fail;

  /* t = g^x mod p */
  dsa_pow_blind(t, params.g, x, params.p, params.q);

  /* y != t */
  if (mpz_cmp(t, y) != 0)
    goto fail;

  result = 1;
fail:
  dsa_params_clear(&params);
  mpz_clear(y);
  mpz_clear(x);
  mpz_clear(t);
  return result;
}

int
bcrypto_dsa_privkey_export(uint8_t *out,
                           size_t *out_len,
                           const bcrypto_dsa_key_t *key) {
  return 0;
}

int
bcrypto_dsa_privkey_import(bcrypto_dsa_key_t *out,
                           const uint8_t *raw, size_t raw_len) {
  return 0;
}

int
bcrypto_dsa_privkey_export_pkcs8(uint8_t *out,
                                 size_t *out_len,
                                 const bcrypto_dsa_key_t *key) {
  return 0;
}

int
bcrypto_dsa_privkey_import_pkcs8(bcrypto_dsa_key_t *key,
                                 const uint8_t *raw, size_t raw_len) {
  return 0;
}

int
bcrypto_dsa_pubkey_verify(const bcrypto_dsa_key_t *key) {
  int result = 0;
  struct dsa_params params;
  mpz_t y, x;

  dsa_params_init(&params);
  mpz_init(y);
  mpz_init(x);

  bcrypto_dsa_key2pub(&params, y, key);

  if (!bcrypto_dsa_sane_pubkey(&params, y))
    goto fail;

  /* x := y^q mod p */
  mpz_powm(x, y, params.q, params.p);

  if (mpz_cmp_ui(x, 1) != 0)
    goto fail;

  result = 1;
fail:
  dsa_params_clear(&params);
  mpz_clear(y);
  mpz_clear(x);
  return result;
}

int
bcrypto_dsa_pubkey_export(uint8_t *out,
                          size_t *out_len,
                          const bcrypto_dsa_key_t *key) {
  return 0;
}

int
bcrypto_dsa_pubkey_import(bcrypto_dsa_key_t *out,
                          const uint8_t *raw, size_t raw_len) {
  return 0;
}

int
bcrypto_dsa_pubkey_export_spki(uint8_t *out,
                               size_t *out_len,
                               const bcrypto_dsa_key_t *key) {
  return 0;
}

int
bcrypto_dsa_pubkey_import_spki(bcrypto_dsa_key_t *out,
                               const uint8_t *raw, size_t raw_len) {
  return 0;
}

int
bcrypto_dsa_sig_export(uint8_t *out,
                       size_t *out_len,
                       const uint8_t *sig,
                       size_t sig_len,
                       size_t size) {
  int result = 0;
  struct dsa_signature signature;

  if (size == 0)
    size = sig_len >> 1;

  dsa_signature_init(&signature);

  if (sig_len == 0 || (sig_len & 1))
    goto fail;

  if (sig_len != size * 2)
    goto fail;

  if (size > 66)
    goto fail;

  bcrypto_dsa_rs2sig(&signature, sig, size);

  if (!bcrypto_dsa_sig2der(out, out_len, &signature, size))
    goto fail;

  result = 1;
fail:
  dsa_signature_clear(&signature);
  return result;
}

int
bcrypto_dsa_sig_import(uint8_t *out,
                       const uint8_t *sig,
                       size_t sig_len,
                       size_t size) {
  int result = 0;
  struct dsa_signature signature;

  dsa_signature_init(&signature);

  if (sig_len == 0)
    goto fail;

  if (size == 0 || size > 66)
    goto fail;

  if (!bcrypto_dsa_der2sig(&signature, sig, sig_len, size))
    goto fail;

  bcrypto_dsa_sig2rs(out, &signature, size);
  result = 1;
fail:
  dsa_signature_clear(&signature);
  return result;
}

int
bcrypto_dsa_sign(uint8_t *out,
                 const uint8_t *msg,
                 size_t msg_len,
                 const bcrypto_dsa_key_t *key) {
  int result = 0;
  struct dsa_params params;
  struct dsa_signature signature;
  mpz_t y, x;

  dsa_params_init(&params);
  dsa_signature_init(&signature);
  mpz_init(y);
  mpz_init(x);

  bcrypto_dsa_key2priv(&params, y, x, key);

  if (!bcrypto_dsa_sane_privkey(&params, y, x))
    goto fail;

  if (!dsa_sign(&params, x, NULL,
                (nettle_random_func *)bcrypto_rng,
                msg_len, msg, &signature)) {
    goto fail;
  }

  bcrypto_dsa_sig2rs(out, &signature, dsa_mpz_bytelen(params.q));

  result = 1;
fail:
  dsa_params_clear(&params);
  dsa_signature_clear(&signature);
  mpz_clear(y);
  mpz_clear(x);
  return result;
}

int
bcrypto_dsa_sign_der(uint8_t *out,
                     size_t *out_len,
                     const uint8_t *msg,
                     size_t msg_len,
                     const bcrypto_dsa_key_t *key) {
  int result = 0;
  struct dsa_params params;
  struct dsa_signature signature;
  mpz_t y, x;

  dsa_params_init(&params);
  dsa_signature_init(&signature);
  mpz_init(y);
  mpz_init(x);

  bcrypto_dsa_key2priv(&params, y, x, key);

  if (!bcrypto_dsa_sane_privkey(&params, y, x))
    goto fail;

  if (!dsa_sign(&params, x, NULL,
                (nettle_random_func *)bcrypto_rng,
                msg_len, msg, &signature)) {
    goto fail;
  }

  if (!bcrypto_dsa_sig2der(out, out_len, &signature,
                           dsa_mpz_bytelen(params.q))) {
    goto fail;
  }

  result = 1;
fail:
  dsa_params_clear(&params);
  dsa_signature_clear(&signature);
  mpz_clear(y);
  mpz_clear(x);
  return result;
}

int
bcrypto_dsa_verify(const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *sig,
                   size_t sig_len,
                   const bcrypto_dsa_key_t *key) {
  int result = 0;
  struct dsa_params params;
  struct dsa_signature signature;
  mpz_t y;
  size_t qsize;

  dsa_params_init(&params);
  dsa_signature_init(&signature);
  mpz_init(y);

  bcrypto_dsa_key2pub(&params, y, key);

  if (!bcrypto_dsa_sane_pubkey(&params, y))
    goto fail;

  qsize = dsa_mpz_bytelen(params.q);

  if (sig_len != qsize * 2)
    goto fail;

  bcrypto_dsa_rs2sig(&signature, sig, qsize);

  if (mpz_cmp_ui(signature.r, 0) == 0
      || mpz_cmp(signature.r, params.q) >= 0) {
    goto fail;
  }

  if (mpz_cmp_ui(signature.s, 0) == 0
      || mpz_cmp(signature.s, params.q) >= 0) {
    goto fail;
  }

  if (!dsa_verify(&params, y, msg_len, msg, &signature))
    goto fail;

  result = 1;
fail:
  dsa_params_clear(&params);
  dsa_signature_clear(&signature);
  mpz_clear(y);
  return result;
}

int
bcrypto_dsa_verify_der(const uint8_t *msg,
                       size_t msg_len,
                       const uint8_t *sig,
                       size_t sig_len,
                       const bcrypto_dsa_key_t *key) {
  int result = 0;
  struct dsa_params params;
  struct dsa_signature signature;
  mpz_t y;

  dsa_params_init(&params);
  dsa_signature_init(&signature);
  mpz_init(y);

  bcrypto_dsa_key2pub(&params, y, key);

  if (!bcrypto_dsa_sane_pubkey(&params, y))
    goto fail;

  if (sig_len == 0)
    goto fail;

  if (!bcrypto_dsa_der2sig(&signature, sig, sig_len,
                           dsa_mpz_bytelen(params.q))) {
    goto fail;
  }

  if (mpz_cmp_ui(signature.r, 0) == 0
      || mpz_cmp(signature.r, params.q) >= 0) {
    goto fail;
  }

  if (mpz_cmp_ui(signature.s, 0) == 0
      || mpz_cmp(signature.s, params.q) >= 0) {
    goto fail;
  }

  if (!dsa_verify(&params, y, msg_len, msg, &signature))
    goto fail;

  result = 1;
fail:
  dsa_params_clear(&params);
  dsa_signature_clear(&signature);
  mpz_clear(y);
  return result;
}

int
bcrypto_dsa_derive(uint8_t *out,
                   size_t *out_len,
                   const bcrypto_dsa_key_t *key_pub,
                   const bcrypto_dsa_key_t *key_prv) {
  int result = 0;
  struct dsa_params pub;
  struct dsa_params prv;
  mpz_t yp, y, x;

  dsa_params_init(&pub);
  dsa_params_init(&prv);
  mpz_init(yp);
  mpz_init(y);
  mpz_init(x);

  bcrypto_dsa_key2pub(&pub, yp, key_pub);
  bcrypto_dsa_key2priv(&prv, y, x, key_prv);

  if (!bcrypto_dsa_sane_pubkey(&pub, yp))
    goto fail;

  if (!bcrypto_dsa_sane_privkey(&prv, y, x))
    goto fail;

  if (mpz_cmp(pub.p, prv.p) != 0
      || mpz_cmp(pub.q, prv.q) != 0
      || mpz_cmp(pub.g, prv.g) != 0) {
    goto fail;
  }

  /* secret := y^x mod p */
  dsa_pow_blind(y, yp, x, prv.p, prv.q);

  if (mpz_sgn(y) == 0)
    goto fail;

  *out_len = dsa_mpz_bytelen(pub.p);
  dsa_mpz_pad(out, *out_len, y);

  result = 1;
fail:
  dsa_params_clear(&pub);
  dsa_params_clear(&prv);
  mpz_clear(yp);
  mpz_clear(y);
  mpz_clear(x);
  return result;
}
