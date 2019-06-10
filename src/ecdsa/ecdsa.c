#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "ecdsa.h"

#include "../random/random.h"
#include "../nettle/ecc-internal.h"
#include "../nettle/ecc.h"
#include "../nettle/ecdsa.h"
#include "../bn/bmpz-impl.h"
#include "../dsa/dsa.h"
#include "../hash/hash.h"

/*
 * Helpers
 */

static inline size_t
ecc_mpz_bitlen(const mpz_t n) {
  if (mpz_sgn(n) == 0)
    return 0;

  return mpz_sizeinbase(n, 2);
}

#define ecc_mpz_bytelen(n) \
  (ecc_mpz_bitlen((n)) + 7) / 8

#define ecc_mpz_import(ret, data, len) \
  mpz_import((ret), (len), 1, sizeof((data)[0]), 0, 0, (data))

#define ecc_mpz_export(data, size, n) \
  mpz_export((data), (size), 1, sizeof((data)[0]), 0, 0, (n));

static inline void
ecc_mpz_pad(void *out, size_t size, const mpz_t n) {
  size_t len = ecc_mpz_bytelen(n);

  assert(len <= size);

  size_t pos = size - len;

  memset(out, 0x00, pos);

  ecc_mpz_export(out + pos, NULL, n);
}

static const struct ecc_curve *
ecc_get_curve(int type) {
  switch (type) {
    case BCRYPTO_CURVE_P192:
      return &nettle_secp_192r1;
    case BCRYPTO_CURVE_P224:
      return &nettle_secp_224r1;
    case BCRYPTO_CURVE_P256:
      return &nettle_secp_256r1;
    case BCRYPTO_CURVE_P384:
      return &nettle_secp_384r1;
    case BCRYPTO_CURVE_P521:
      return &nettle_secp_521r1;
    default:
      return NULL;
  }
}

static size_t
ecc_field_bits(int type) {
  const struct ecc_curve *ecc = ecc_get_curve(type);

  if (ecc == NULL)
    return 0;

  return (size_t)ecc->p.bit_size;
}

static size_t
ecc_scalar_bits(int type) {
  const struct ecc_curve *ecc = ecc_get_curve(type);

  if (ecc == NULL)
    return 0;

  return (size_t)ecc->q.bit_size;
}

static size_t
ecc_field_length(int type) {
  return (ecc_field_bits(type) + 7) / 8;
}

static size_t
ecc_scalar_length(int type) {
  return (ecc_scalar_bits(type) + 7) / 8;
}

static size_t
ecc_point_length(int type, int compact) {
  size_t len = ecc_field_length(type);

  if (len == 0)
    return 0;

  if (compact)
    return 1 + ecc_field_length(type);

  return 1 + ecc_field_length(type) * 2;
}

static size_t
ecc_signature_length(int type) {
  return ecc_scalar_length(type) * 2;
}

static size_t
ecc_der_length(int type) {
  size_t len = ecc_signature_length(type);

  if (len == 0)
    return 0;

  return 9 + len;
}

static int
ecc_point_set_x(struct ecc_point *p, const mpz_t x, int sign) {
  int result = 0;
  mp_size_t size = p->ecc->p.size;
  mpz_t m, a, b, ax, y2, y;

  mpz_roinit_n(m, p->ecc->p.m, size);
  mpz_init(a);
  mpz_roinit_n(b, p->ecc->b, size);
  mpz_init(ax);
  mpz_init(y2);
  mpz_init(y);

  if (mpz_sgn(x) < 0 || mpz_limbs_cmp(x, p->ecc->p.m, size) >= 0)
    goto fail;

  /*
   * Nettle doesn't provide the `a`
   * coefficient of the curve, but
   * luckily all our curves have a
   * value of `-3 mod p`.
   */

  /* a = -3 mod p */
  mpz_set(a, m);
  mpz_sub_ui(a, a, 3);

  /* ax = (a * x) mod p */
  mpz_mul(ax, a, x);
  mpz_mod(ax, ax, m);

  /* y2 = (x^3 + ax + b) mod p */
  mpz_powm_ui(y2, x, 3, m);
  mpz_add(y2, y2, ax);
  mpz_add(y2, y2, b);
  mpz_mod(y2, y2, m);

  /*
   * We could use p->ecc->sqrt() right now,
   * but it's not implemented for the NIST
   * curves. All curves except p224 satisfy
   * `p mod 4 == 3`, otherwise we could do
   * a fast square root for all of them.
   *
   * p192 = p mod 4 == 3
   * p224 = nothing (not `p mod 8 == 5` either)
   * p256 = p mod 4 == 3
   * p384 = p mod 4 == 3
   * p521 = p mod 4 == 3
   */

  /* y = sqrt(y2) mod p */
  if (!bmpz_sqrtp(y, y2, m))
    goto fail;

  /* if y & 1 != sign */
  if ((mpz_odd_p(y) != 0) != (sign != 0)) {
    /* y = -y mod p */
    mpz_neg(y, y);
    mpz_mod(y, y, m);
  }

  mpz_limbs_copy(p->p, x, size);
  mpz_limbs_copy(p->p + size, y, size);
  result = 1;
fail:
  mpz_clear(a);
  mpz_clear(ax);
  mpz_clear(y2);
  mpz_clear(y);
  return result;
}

static void
ecc_point_encode(uint8_t *raw, size_t *raw_len,
                 struct ecc_point *p, int compact) {
  mp_size_t size = p->ecc->p.size;
  size_t bytes = ((size_t)p->ecc->p.bit_size + 7) / 8;
  mpz_t x, y;
  mpz_roinit_n(x, p->p, size);
  mpz_roinit_n(y, p->p + size, size);

  if (compact) {
    raw[0] = 0x02 | (mpz_odd_p(y) != 0);
    ecc_mpz_pad(&raw[1], bytes, x);
    *raw_len = 1 + bytes;
  } else {
    raw[0] = 0x04;
    ecc_mpz_pad(&raw[1], bytes, x);
    ecc_mpz_pad(&raw[1 + bytes], bytes, y);
    *raw_len = 1 + bytes * 2;
  }
}

static int
ecc_point_decode(struct ecc_point *p,
                 const uint8_t *raw,
                 size_t raw_len) {
  int result = 0;
  size_t bytes = ((size_t)p->ecc->p.bit_size + 7) / 8;
  mpz_t x, y;

  mpz_init(x);
  mpz_init(y);

  if (raw_len < 1 + bytes)
    goto fail;

  switch (raw[0]) {
    case 0x02:
    case 0x03: {
      if (raw_len != 1 + bytes)
        goto fail;

      ecc_mpz_import(x, &raw[1], bytes);

      if (!ecc_point_set_x(p, x, raw[0] & 1))
        goto fail;

      break;
    }

    case 0x04: {
      if (raw_len != 1 + bytes * 2)
        goto fail;

      ecc_mpz_import(x, &raw[1], bytes);
      ecc_mpz_import(y, &raw[1 + bytes], bytes);

      if (!ecc_point_set(p, x, y))
        goto fail;

      break;
    }

    case 0x06:
    case 0x07: {
      if (raw_len != 1 + bytes * 2)
        goto fail;

      if ((raw[0] & 1) != (raw[raw_len - 1] & 1))
        goto fail;

      ecc_mpz_import(x, &raw[1], bytes);
      ecc_mpz_import(y, &raw[1 + bytes], bytes);

      if (!ecc_point_set(p, x, y))
        goto fail;

      break;
    }

    default: {
      goto fail;
    }
  }

  result = 1;
fail:
  mpz_clear(x);
  mpz_clear(y);
  return result;
}

#define ECC_REAL_ADD_JJJ_ITCH(size) (ECC_ADD_JJJ_ITCH(size))

static void
ecc_real_add_jjj(const struct ecc_curve *ecc,
                 mp_limb_t *out,
                 const mp_limb_t *p,
                 const mp_limb_t *q,
                 mp_limb_t *scratch) {
  mp_size_t size = ecc->p.size;

  assert(ECC_ADD_JJJ_ITCH(size) >= ECC_DUP_JJ_ITCH(size));

  /* O + P = P */
  if (mpn_zero_p(p + size * 2, size)) {
    if (out != q)
      mpn_copyi(out, q, size * 3);
    return;
  }

  /* P + O = P */
  if (mpn_zero_p(q + size * 2, size)) {
    if (out != p)
      mpn_copyi(out, p, size * 3);
    return;
  }

  /* P + P = 2P */
  if (mpn_cmp(p, q, size * 3) == 0)
    ecc_dup_jj(ecc, out, p, scratch);
  else
    ecc_add_jjj(ecc, out, p, q, scratch);
}

#define ECC_REAL_ADD_JJA_ITCH(size) (ECC_MAX_SIZE * 3 + ECC_ADD_JJJ_ITCH(size))

static void
ecc_real_add_jja(const struct ecc_curve *ecc,
                 mp_limb_t *out,
                 const mp_limb_t *p,
                 const mp_limb_t *q,
                 mp_limb_t *scratch) {
  mp_limb_t *r = &scratch[0 * ECC_MAX_SIZE];
  mp_limb_t *scr = &scratch[3 * ECC_MAX_SIZE];
  mp_size_t size = ecc->p.size;

  assert(ECC_ADD_JJA_ITCH(size) >= ECC_DUP_JJ_ITCH(size)); /* normal */
  assert(ECC_ADD_JJA_ITCH(size) < ECC_ADD_JJJ_ITCH(size)); /* redc, i.e. p256 */
  assert(ECC_ADD_JJA_ITCH(size) >= ECC_J_TO_A_ITCH(size));

  /* redc curves do not return zero for P + P */
  /* redc curves do not return correct result for for 2P + -P */
  if (ecc->use_redc) {
    ecc_a_to_j(ecc, r, q);
    ecc_real_add_jjj(ecc, out, p, r, scr);
    return;
  }

  /*
   * NOTE: Behaviour for corner cases:
   *   + p = 0   ==>  r = 0 (invalid except if also q = 0)
   *   + q = 0   ==>  r = invalid
   *   + p = -q  ==>  r = 0, correct!
   *   + p = q   ==>  r = 0, invalid
   */

  /* O + P = P */
  if (mpn_zero_p(p + size * 2, size)) {
    ecc_a_to_j(ecc, out, q);
    return;
  }

  /* P + O = P */
  if (mpn_zero_p(q, size * 2)) {
    if (out != p)
      mpn_copyi(out, p, size * 3);
    return;
  }

  ecc_add_jja(ecc, r, p, q, scr);

  /* P + P = 2P */
  if (mpn_zero_p(r, size * 3))
    ecc_dup_jj(ecc, out, p, scr);
  else
    mpn_copyi(out, r, size * 3);
}

#define ECC_REAL_ADD_JAA_ITCH(size) \
  (ECC_MAX_SIZE * 3 + ECC_REAL_ADD_JJA_ITCH(size))

static void
ecc_real_add_jaa(const struct ecc_curve *ecc,
                 mp_limb_t *out,
                 const mp_limb_t *p,
                 const mp_limb_t *q,
                 mp_limb_t *scratch) {
  mp_limb_t *r = &scratch[0 * ECC_MAX_SIZE];
  mp_limb_t *scr = &scratch[3 * ECC_MAX_SIZE];

  ecc_a_to_j(ecc, r, p);
  ecc_real_add_jja(ecc, out, r, q, scr);
}

#define ECC_MUL_ADD_ITCH(size) (ECC_MAX_SIZE * 6 + ECC_MUL_A_ITCH(size))

static void
ecc_mul_add(const struct ecc_curve *ecc,
            mp_limb_t *out,
            const mp_limb_t *p1,
            const mp_limb_t *c1,
            const mp_limb_t *p2,
            const mp_limb_t *c2,
            mp_limb_t *scratch) {
  mp_size_t size = ecc->p.size;
  mp_limb_t *r1 = &scratch[0 * ECC_MAX_SIZE];
  mp_limb_t *r2 = &scratch[3 * ECC_MAX_SIZE];
  mp_limb_t *scr = &scratch[6 * ECC_MAX_SIZE];

  assert(ECC_MUL_A_ITCH(size) >= ECC_MUL_G_ITCH(size));
  assert(ECC_MUL_A_ITCH(size) >= ECC_ADD_JJJ_ITCH(size));

  if (p1 == NULL)
    ecc_mul_g(ecc, r1, c1, scr);
  else
    ecc_mul_a(ecc, r1, c1, p1, scr);

  ecc_mul_a(ecc, r2, c2, p2, scr);
  ecc_real_add_jjj(ecc, out, r1, r2, scr);
}

static int
ecc_point_add(struct ecc_point *r,
              const struct ecc_point *a,
              const struct ecc_point *b) {
  int result = 0;
  const struct ecc_curve *ecc = r->ecc;
  mp_size_t size = ecc->p.size;
  mp_limb_t *limbs = NULL;
  mp_limb_t *j, *s;

  assert(ECC_REAL_ADD_JAA_ITCH(size) >= ECC_J_TO_A_ITCH(size));

  limbs = gmp_alloc_limbs(3 * size + ECC_REAL_ADD_JAA_ITCH(size));

  if (limbs == NULL)
    goto fail;

  /* Setup points and scratch. */
  j = &limbs[0];
  s = &limbs[3 * size];

  ecc_real_add_jaa(ecc, j, a->p, b->p, s);

  /* Check for infinity. */
  if (mpn_zero_p(j + 2 * size, size))
    goto fail;

  /* Reuse scratch. */
  ecc_j_to_a(ecc, 0, r->p, j, s);

  result = 1;
fail:
  if (limbs != NULL)
    gmp_free_limbs(limbs, 3 * size + ECC_REAL_ADD_JAA_ITCH(size));

  return result;
}

static void
ecc_scalar_encode(uint8_t *raw, const struct ecc_scalar *s) {
  mp_size_t size = s->ecc->p.size;
  size_t bytes = ((size_t)s->ecc->p.bit_size + 7) / 8;
  mpz_t z;
  mpz_roinit_n(z, s->p, size);
  ecc_mpz_pad(raw, bytes, z);
}

static int
ecc_scalar_decode(struct ecc_scalar *s, const uint8_t *raw) {
  int result = 0;
  size_t bytes = ((size_t)s->ecc->q.bit_size + 7) / 8;
  mpz_t z;

  mpz_init(z);

  ecc_mpz_import(z, raw, bytes);

  if (!ecc_scalar_set(s, z))
    goto fail;

  result = 1;
fail:
  mpz_clear(z);
  return result;
}

static int
ecc_scalar_decode_lax(struct ecc_scalar *s, const uint8_t *raw) {
  int result = 0;
  mp_size_t size = s->ecc->p.size;
  size_t bytes = ((size_t)s->ecc->q.bit_size + 7) / 8;
  mpz_t z;

  mpz_init(z);

  ecc_mpz_import(z, raw, bytes);

  if (mpz_limbs_cmp(z, s->ecc->q.m, size) >= 0)
    goto fail;

  mpz_limbs_copy(s->p, z, size);

  result = 1;
fail:
  mpz_clear(z);
  return result;
}

size_t
bcrypto_ecdsa_field_bits(int type) {
  return ecc_field_bits(type);
}

size_t
bcrypto_ecdsa_field_length(int type) {
  return ecc_field_length(type);
}

size_t
bcrypto_ecdsa_scalar_length(int type) {
  return ecc_scalar_length(type);
}

size_t
bcrypto_ecdsa_sig_length(int type) {
  return ecc_signature_length(type);
}

int
bcrypto_ecdsa_privkey_generate(int type, uint8_t *out) {
  const struct ecc_curve *ecc = ecc_get_curve(type);
  struct ecc_scalar s;

  if (ecc == NULL)
    return 0;

  ecc_scalar_init(&s, ecc);
  ecc_scalar_random(&s, NULL, bcrypto_rng);
  ecc_scalar_encode(out, &s);
  ecc_scalar_clear(&s);

  return 1;
}

int
bcrypto_ecdsa_privkey_verify(int type, const uint8_t *key) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  struct ecc_scalar s;

  if (ecc == NULL)
    return 0;

  ecc_scalar_init(&s, ecc);

  if (!ecc_scalar_decode(&s, key))
    goto fail;

  result = 1;
fail:
  ecc_scalar_clear(&s);
  return result;
}

int
bcrypto_ecdsa_privkey_export(int type,
                             uint8_t *out,
                             size_t *out_len,
                             const uint8_t *key,
                             int compress) {
  return 0;
}

int
bcrypto_ecdsa_privkey_import(int type,
                             uint8_t *out,
                             const uint8_t *raw,
                             size_t raw_len) {
  return 0;
}

int
bcrypto_ecdsa_privkey_export_pkcs8(int type,
                                   uint8_t *out,
                                   size_t *out_len,
                                   const uint8_t *key,
                                   int compress) {
  return 0;
}

int
bcrypto_ecdsa_privkey_import_pkcs8(int type,
                                   uint8_t *out,
                                   const uint8_t *raw,
                                   size_t raw_len) {
  return 0;
}

int
bcrypto_ecdsa_privkey_tweak_add(int type,
                                uint8_t *out,
                                const uint8_t *key,
                                const uint8_t *tweak) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  size_t bytes = ecc_scalar_length(type);
  mpz_t n, s, t;

  if (ecc == NULL)
    return 0;

  mpz_roinit_n(n, ecc->q.m, ecc->p.size);
  mpz_init(s);
  mpz_init(t);

  ecc_mpz_import(s, key, bytes);
  ecc_mpz_import(t, tweak, bytes);

  if (mpz_sgn(s) == 0 || mpz_cmp(s, n) >= 0)
    goto fail;

  if (mpz_cmp(t, n) >= 0)
    goto fail;

  mpz_add(s, s, t);
  mpz_mod(s, s, n);

  if (mpz_sgn(s) == 0)
    goto fail;

  ecc_mpz_pad(out, bytes, s);
  result = 1;
fail:
  mpz_clear(s);
  mpz_clear(t);
  return result;
}

int
bcrypto_ecdsa_privkey_tweak_mul(int type,
                                uint8_t *out,
                                const uint8_t *key,
                                const uint8_t *tweak) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  mp_size_t size = ecc != NULL ? ecc->p.size : 0;
  struct ecc_scalar s, t, r;

  if (ecc == NULL)
    return 0;

  ecc_scalar_init(&s, ecc);
  ecc_scalar_init(&t, ecc);

  r.ecc = ecc;
  r.p = gmp_alloc_limbs(2 * ecc->p.size);

  if (r.p == NULL)
    goto fail;

  if (!ecc_scalar_decode(&s, key))
    goto fail;

  if (!ecc_scalar_decode(&t, tweak))
    goto fail;

  /* NOTE: mul needs 2*m->size limbs at rp */
  ecc_mod_mul(&ecc->q, r.p, s.p, t.p);

  if (mpn_zero_p(r.p, size))
    goto fail;

  ecc_scalar_encode(out, &r);
  result = 1;
fail:
  ecc_scalar_clear(&s);
  ecc_scalar_clear(&t);

  if (r.p != NULL)
    gmp_free_limbs(r.p, 2 * ecc->p.size);

  return result;
}

int
bcrypto_ecdsa_privkey_reduce(int type,
                             uint8_t *out,
                             const uint8_t *key,
                             size_t key_len) {
  const struct ecc_curve *ecc = ecc_get_curve(type);
  size_t bytes = ecc_scalar_length(type);
  mpz_t n, z;

  if (ecc == NULL)
    return 0;

  mpz_roinit_n(n, ecc->q.m, ecc->p.size);

  if (key_len > bytes)
    key_len = bytes;

  mpz_init(z);
  ecc_mpz_import(z, key, key_len);
  mpz_mod(z, z, n);
  ecc_mpz_pad(out, bytes, z);
  mpz_clear(z);

  return 1;
}

int
bcrypto_ecdsa_privkey_negate(int type, uint8_t *out, const uint8_t *key) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  struct ecc_scalar s;

  if (ecc == NULL)
    return 0;

  ecc_scalar_init(&s, ecc);

  if (!ecc_scalar_decode_lax(&s, key))
    goto fail;

  ecc_mod_sub(&ecc->q, s.p, ecc->q.m, s.p);

  ecc_scalar_encode(out, &s);
  result = 1;
fail:
  ecc_scalar_clear(&s);
  return result;
}

int
bcrypto_ecdsa_privkey_invert(int type, uint8_t *out, const uint8_t *key) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  mp_size_t size = ecc != NULL ? ecc->p.size : 0;
  mp_limb_t *scratch;
  struct ecc_scalar s, r;

  if (ecc == NULL)
    return 0;

  ecc_scalar_init(&s, ecc);

  scratch = gmp_alloc_limbs(2 * ecc->p.size + ecc->q.invert_itch);

  if (scratch == NULL)
    goto fail;

  r.ecc = ecc;
  r.p = scratch;

  if (!ecc_scalar_decode(&s, key))
    goto fail;

  /* NOTE: ecc_mod_inv needs 2*m->size limbs at rp */
  ecc->q.invert(&ecc->q, r.p, s.p, scratch + 2 * ecc->p.size);

  if (mpn_zero_p(r.p, size))
    goto fail;

  ecc_scalar_encode(out, &r);
  result = 1;
fail:
  ecc_scalar_clear(&s);

  if (scratch != NULL)
    gmp_free_limbs(scratch, 2 * ecc->p.size + ecc->q.invert_itch);

  return result;
}

int
bcrypto_ecdsa_pubkey_create(int type,
                            uint8_t *out,
                            size_t *out_len,
                            const uint8_t *key,
                            int compress) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  struct ecc_scalar s;
  struct ecc_point p;

  if (ecc == NULL)
    return 0;

  ecc_scalar_init(&s, ecc);
  ecc_point_init(&p, ecc);

  if (!ecc_scalar_decode(&s, key))
    goto fail;

  ecc_point_mul_g(&p, &s);
  ecc_point_encode(out, out_len, &p, compress);

  result = 1;
fail:
  ecc_scalar_clear(&s);
  ecc_point_clear(&p);
  return result;
}

int
bcrypto_ecdsa_pubkey_convert(int type,
                             uint8_t *out,
                             size_t *out_len,
                             const uint8_t *key,
                             size_t key_len,
                             int compress) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  struct ecc_point p;

  if (ecc == NULL)
    return 0;

  ecc_point_init(&p, ecc);

  if (!ecc_point_decode(&p, key, key_len))
    goto fail;

  ecc_point_encode(out, out_len, &p, compress);

  result = 1;
fail:
  ecc_point_clear(&p);
  return result;
}

int
bcrypto_ecdsa_pubkey_verify(int type, const uint8_t *key, size_t key_len) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  struct ecc_point p;

  if (ecc == NULL)
    return 0;

  ecc_point_init(&p, ecc);

  if (!ecc_point_decode(&p, key, key_len))
    goto fail;

  result = 1;
fail:
  ecc_point_clear(&p);
  return result;
}

int
bcrypto_ecdsa_pubkey_export_spki(int type,
                                 uint8_t *out,
                                 size_t *out_len,
                                 const uint8_t *key,
                                 size_t key_len,
                                 int compress) {
  return 0;
}

int
bcrypto_ecdsa_pubkey_import_spki(int type,
                                 uint8_t *out,
                                 const uint8_t *raw,
                                 size_t raw_len) {
  return 0;
}

int
bcrypto_ecdsa_pubkey_tweak_add(int type,
                               uint8_t *out,
                               size_t *out_len,
                               const uint8_t *key,
                               size_t key_len,
                               const uint8_t *tweak,
                               int compress) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  mp_size_t size = ecc != NULL ? ecc->p.size : 0;
  struct ecc_point p, q;
  struct ecc_scalar t;

  if (ecc == NULL)
    return 0;

  ecc_point_init(&p, ecc);
  ecc_point_init(&q, ecc);
  ecc_scalar_init(&t, ecc);

  /* Decode point and scalar. */
  if (!ecc_point_decode(&p, key, key_len))
    goto fail;

  if (!ecc_scalar_decode_lax(&t, tweak))
    goto fail;

  if (mpn_zero_p(t.p, size))
    goto success;

  ecc_point_mul_g(&q, &t);

  /* Check for infinity. */
  /* See: https://github.com/gnutls/nettle/blob/master/ecc.h#L120 */
  if (mpn_zero_p(q.p, 2 * size))
    goto fail;

  if (!ecc_point_add(&p, &p, &q))
    goto fail;

success:
  ecc_point_encode(out, out_len, &p, compress);
  result = 1;
fail:
  ecc_point_clear(&p);
  ecc_point_clear(&q);
  ecc_scalar_clear(&t);
  return result;
}

int
bcrypto_ecdsa_pubkey_tweak_mul(int type,
                               uint8_t *out,
                               size_t *out_len,
                               const uint8_t *key,
                               size_t key_len,
                               const uint8_t *tweak,
                               int compress) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  mp_size_t size = ecc != NULL ? ecc->p.size : 0;
  struct ecc_point r, p;
  struct ecc_scalar t;

  if (ecc == NULL)
    return 0;

  ecc_point_init(&r, ecc);
  ecc_point_init(&p, ecc);
  ecc_scalar_init(&t, ecc);

  if (!ecc_point_decode(&p, key, key_len))
    goto fail;

  if (!ecc_scalar_decode(&t, tweak))
    goto fail;

  ecc_point_mul(&r, &t, &p);

  /* Check for infinity. */
  /* See: https://github.com/gnutls/nettle/blob/master/ecc.h#L120 */
  if (mpn_zero_p(r.p, size * 2))
    goto fail;

  ecc_point_encode(out, out_len, &r, compress);

  result = 1;
fail:
  ecc_point_clear(&r);
  ecc_point_clear(&p);
  ecc_scalar_clear(&t);
  return result;
}

int
bcrypto_ecdsa_pubkey_add(int type,
                         uint8_t *out,
                         size_t *out_len,
                         const uint8_t *key1,
                         size_t key1_len,
                         const uint8_t *key2,
                         size_t key2_len,
                         int compress) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  struct ecc_point p1, p2;

  if (ecc == NULL)
    return 0;

  ecc_point_init(&p1, ecc);
  ecc_point_init(&p2, ecc);

  if (!ecc_point_decode(&p1, key1, key1_len))
    goto fail;

  if (!ecc_point_decode(&p2, key2, key2_len))
    goto fail;

  if (!ecc_point_add(&p1, &p1, &p2))
    goto fail;

  ecc_point_encode(out, out_len, &p1, compress);

  result = 1;
fail:
  ecc_point_clear(&p1);
  ecc_point_clear(&p2);
  return result;
}

int
bcrypto_ecdsa_pubkey_combine(int type,
                             uint8_t *out,
                             size_t *out_len,
                             const uint8_t **keys,
                             size_t *key_lens,
                             size_t length,
                             int compress) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  struct ecc_point point;
  size_t i = 0;
  mp_size_t size = 0;
  mp_limb_t *limbs = NULL;
  mp_limb_t *acc = NULL;
  mp_limb_t *scratch = NULL;

  if (ecc == NULL)
    return 0;

  if (length == 0)
    return 0;

  size = ecc->p.size;

  ecc_point_init(&point, ecc);

  limbs = gmp_alloc_limbs(3 * size + ECC_REAL_ADD_JJA_ITCH(size));

  if (limbs == NULL)
    goto fail;

  acc = &limbs[0];
  scratch = &limbs[3 * size];

  if (!ecc_point_decode(&point, keys[0], key_lens[0]))
    goto fail;

  ecc_a_to_j(ecc, acc, point.p);

  for (i = 1; i < length; i++) {
    if (!ecc_point_decode(&point, keys[i], key_lens[i]))
      goto fail;

    ecc_real_add_jja(ecc, acc, acc, point.p, scratch);
  }

  if (mpn_zero_p(acc + size * 2, size))
    goto fail;

  ecc_j_to_a(ecc, 0, point.p, acc, scratch);
  ecc_point_encode(out, out_len, &point, compress);

  result = 1;
fail:
  ecc_point_clear(&point);

  if (limbs != NULL)
    gmp_free_limbs(limbs, 3 * size + ECC_REAL_ADD_JJA_ITCH(size));

  return result;
}

int
bcrypto_ecdsa_pubkey_negate(int type,
                            uint8_t *out,
                            size_t *out_len,
                            const uint8_t *key,
                            size_t key_len,
                            int compress) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  struct ecc_point p;
  mpz_t m, x, y;

  if (ecc == NULL)
    return 0;

  ecc_point_init(&p, ecc);
  mpz_roinit_n(m, ecc->p.m, ecc->p.size);
  mpz_init(x);
  mpz_init(y);

  if (!ecc_point_decode(&p, key, key_len))
    goto fail;

  ecc_point_get(&p, x, y);

  mpz_sub(y, m, y);
  mpz_mod(y, y, m);

  if (!ecc_point_set(&p, x, y))
    goto fail;

  ecc_point_encode(out, out_len, &p, compress);

  result = 1;
fail:
  ecc_point_clear(&p);
  mpz_clear(x);
  mpz_clear(y);
  return result;
}

int
bcrypto_ecdsa_sig_normalize(int type,
                            uint8_t *out,
                            const uint8_t *sig) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  size_t size = ecc_scalar_length(type);
  struct dsa_signature signature;
  mpz_t n, nh;

  dsa_signature_init(&signature);
  mpz_init(nh);

  if (ecc == NULL)
    goto fail;

  bcrypto_dsa_rs2sig(&signature, sig, size);

  mpz_roinit_n(n, ecc->q.m, ecc->p.size);
  mpz_tdiv_q_2exp(nh, n, 1);

  if (mpz_cmp(signature.s, nh) > 0)
    mpz_sub(signature.s, n, signature.s);

  bcrypto_dsa_sig2rs(out, &signature, size);
  result = 1;
fail:
  dsa_signature_clear(&signature);
  mpz_clear(nh);
  return result;
}

int
bcrypto_ecdsa_sig_normalize_der(int type,
                                uint8_t *out,
                                size_t *out_len,
                                const uint8_t *sig,
                                size_t sig_len) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  size_t size = ecc_scalar_length(type);
  struct dsa_signature signature;
  mpz_t n, nh;

  dsa_signature_init(&signature);
  mpz_init(nh);

  if (ecc == NULL)
    goto fail;

  if (sig_len == 0)
    goto fail;

  if (!bcrypto_dsa_der2sig(&signature, sig, sig_len, size))
    goto fail;

  mpz_roinit_n(n, ecc->q.m, ecc->p.size);
  mpz_tdiv_q_2exp(nh, n, 1);

  if (mpz_cmp(signature.s, nh) > 0)
    mpz_sub(signature.s, n, signature.s);

  if (!bcrypto_dsa_sig2der(out, out_len, &signature, size))
    goto fail;

  result = 1;
fail:
  dsa_signature_clear(&signature);
  mpz_clear(nh);
  return result;
}

int
bcrypto_ecdsa_sig_export(int type,
                         uint8_t *out,
                         size_t *out_len,
                         const uint8_t *sig) {
  int result = 0;
  size_t size = ecc_scalar_length(type);
  struct dsa_signature signature;

  dsa_signature_init(&signature);

  if (size == 0)
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
bcrypto_ecdsa_sig_import(int type,
                         uint8_t *out,
                         const uint8_t *sig,
                         size_t sig_len) {
  int result = 0;
  size_t size = ecc_scalar_length(type);
  struct dsa_signature signature;

  dsa_signature_init(&signature);

  if (size == 0 || sig_len == 0)
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
bcrypto_ecdsa_sig_low_s(int type, const uint8_t *sig) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  size_t size = ecc_scalar_length(type);
  struct dsa_signature signature;
  mpz_t n, nh;

  dsa_signature_init(&signature);
  mpz_init(nh);

  if (ecc == NULL)
    goto fail;

  bcrypto_dsa_rs2sig(&signature, sig, size);

  mpz_roinit_n(n, ecc->q.m, ecc->p.size);
  mpz_tdiv_q_2exp(nh, n, 1);

  if (mpz_cmp(signature.s, nh) > 0)
    goto fail;

  result = 1;
fail:
  dsa_signature_clear(&signature);
  mpz_clear(nh);
  return result;
}

int
bcrypto_ecdsa_sig_low_der(int type, const uint8_t *sig, size_t sig_len) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  size_t size = ecc_scalar_length(type);
  struct dsa_signature signature;
  mpz_t n, nh;

  dsa_signature_init(&signature);
  mpz_init(nh);

  if (ecc == NULL)
    goto fail;

  if (sig_len == 0)
    goto fail;

  if (!bcrypto_dsa_der2sig(&signature, sig, sig_len, size))
    goto fail;

  mpz_roinit_n(n, ecc->q.m, ecc->p.size);
  mpz_tdiv_q_2exp(nh, n, 1);

  if (mpz_cmp(signature.s, nh) > 0)
    goto fail;

  result = 1;
fail:
  dsa_signature_clear(&signature);
  mpz_clear(nh);
  return result;
}

int
bcrypto_ecdsa_sign(int type,
                   uint8_t *out,
                   const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *key) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  size_t size = ecc_scalar_length(type);
  struct ecc_scalar s;
  struct dsa_signature signature;
  mpz_t n, nh;

  if (ecc == NULL)
    return 0;

  ecc_scalar_init(&s, ecc);
  dsa_signature_init(&signature);
  mpz_init(nh);

  if (!ecc_scalar_decode(&s, key))
    goto fail;

  ecdsa_sign(&s, NULL, bcrypto_rng, msg_len, msg, &signature);

  mpz_roinit_n(n, ecc->q.m, ecc->p.size);
  mpz_tdiv_q_2exp(nh, n, 1);

  if (mpz_cmp(signature.s, nh) > 0)
    mpz_sub(signature.s, n, signature.s);

  bcrypto_dsa_sig2rs(out, &signature, size);

  result = 1;
fail:
  ecc_scalar_clear(&s);
  dsa_signature_clear(&signature);
  mpz_clear(nh);
  return result;
}

int
bcrypto_ecdsa_sign_der(int type,
                       uint8_t *out,
                       size_t *out_len,
                       const uint8_t *msg,
                       size_t msg_len,
                       const uint8_t *key) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  size_t size = ecc_scalar_length(type);
  struct ecc_scalar s;
  struct dsa_signature signature;
  mpz_t n, nh;

  if (ecc == NULL)
    return 0;

  ecc_scalar_init(&s, ecc);
  dsa_signature_init(&signature);
  mpz_init(nh);

  if (!ecc_scalar_decode(&s, key))
    goto fail;

  ecdsa_sign(&s, NULL, bcrypto_rng, msg_len, msg, &signature);

  mpz_roinit_n(n, ecc->q.m, ecc->p.size);
  mpz_tdiv_q_2exp(nh, n, 1);

  if (mpz_cmp(signature.s, nh) > 0)
    mpz_sub(signature.s, n, signature.s);

  if (!bcrypto_dsa_sig2der(out, out_len, &signature, size))
    goto fail;

  result = 1;
fail:
  ecc_scalar_clear(&s);
  dsa_signature_clear(&signature);
  mpz_clear(nh);
  return result;
}

int
bcrypto_ecdsa_sign_recoverable(int type,
                               uint8_t *out,
                               int *param,
                               const uint8_t *msg,
                               size_t msg_len,
                               const uint8_t *key) {
  uint8_t Q[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  uint8_t Qprime[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t len;
  int i = 0;

  if (!bcrypto_ecdsa_sign(type, out, msg, msg_len, key))
    return 0;

  if (!bcrypto_ecdsa_pubkey_create(type, Q, &len, key, 0))
    return 0;

  for (; i < 4; i++) {
    if (!bcrypto_ecdsa_recover(type, Qprime, &len, msg, msg_len, out, i, 0))
      continue;

    if (memcmp(&Qprime[0], &Q[0], len) != 0)
      continue;

    *param = i;

    return 1;
  }

  return 0;
}

int
bcrypto_ecdsa_sign_recoverable_der(int type,
                                   uint8_t *out,
                                   size_t *out_len,
                                   int *param,
                                   const uint8_t *msg,
                                   size_t msg_len,
                                   const uint8_t *key) {
  if (!bcrypto_ecdsa_sign_recoverable(type, out, param, msg, msg_len, key))
    return 0;

  return bcrypto_ecdsa_sig_export(type, out, out_len, out);
}

int
bcrypto_ecdsa_verify(int type,
                     const uint8_t *msg,
                     size_t msg_len,
                     const uint8_t *sig,
                     const uint8_t *key,
                     size_t key_len) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  size_t size = ecc_scalar_length(type);
  struct ecc_point p;
  struct dsa_signature signature;

  if (ecc == NULL)
    return 0;

  ecc_point_init(&p, ecc);
  dsa_signature_init(&signature);

  if (!ecc_point_decode(&p, key, key_len))
    goto fail;

  bcrypto_dsa_rs2sig(&signature, sig, size);

  if (!ecdsa_verify(&p, msg_len, msg, &signature))
    goto fail;

  result = 1;
fail:
  ecc_point_clear(&p);
  dsa_signature_clear(&signature);
  return result;
}

int
bcrypto_ecdsa_verify_der(int type,
                         const uint8_t *msg,
                         size_t msg_len,
                         const uint8_t *sig,
                         size_t sig_len,
                         const uint8_t *key,
                         size_t key_len) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  size_t size = ecc_scalar_length(type);
  struct ecc_point p;
  struct dsa_signature signature;

  if (ecc == NULL)
    return 0;

  ecc_point_init(&p, ecc);
  dsa_signature_init(&signature);

  if (!ecc_point_decode(&p, key, key_len))
    goto fail;

  if (sig_len == 0)
    goto fail;

  if (!bcrypto_dsa_der2sig(&signature, sig, sig_len, size))
    goto fail;

  if (!ecdsa_verify(&p, msg_len, msg, &signature))
    goto fail;

  result = 1;
fail:
  ecc_point_clear(&p);
  dsa_signature_clear(&signature);
  return result;
}

static int
bcrypto_ecdsa_recover_inner(int type,
                            uint8_t *out,
                            size_t *out_len,
                            const uint8_t *msg,
                            size_t msg_len,
                            const struct dsa_signature *signature,
                            int param,
                            int compress) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  mpz_t p, n, m, x, pn, ri, s1, s2;
  struct ecc_point r2, lhs, rhs, Q;
  struct ecc_scalar s1_, s2_;
  size_t bits;

  if (param < 0 || (param & 3) != param)
    return 0;

  if (ecc == NULL)
    return 0;

  mpz_roinit_n(p, ecc->p.m, ecc->p.size);
  mpz_roinit_n(n, ecc->q.m, ecc->p.size);
  bits = ecc_mpz_bitlen(n);

  mpz_init(m);
  mpz_init(x);
  mpz_init(pn);
  mpz_init(ri);
  mpz_init(s1);
  mpz_init(s2);
  ecc_point_init(&r2, ecc);
  ecc_point_init(&lhs, ecc);
  ecc_point_init(&rhs, ecc);
  ecc_point_init(&Q, ecc);
  ecc_scalar_init(&s1_, ecc);
  ecc_scalar_init(&s2_, ecc);

  if (mpz_cmp_ui(signature->r, 0) == 0
      || mpz_cmp(signature->r, n) >= 0) {
    goto fail;
  }

  if (mpz_cmp_ui(signature->s, 0) == 0
      || mpz_cmp(signature->s, n) >= 0) {
    goto fail;
  }

  if (msg_len > (bits + 7) / 8)
    msg_len = (bits + 7) / 8;

  ecc_mpz_import(m, msg, msg_len);

  if (8 * msg_len > bits)
    mpz_tdiv_q_2exp(m, m, 8 * msg_len - bits);

  int sign = param & 1;
  int second = param >> 1;

  mpz_set(x, signature->r);

  if (second) {
    mpz_mod(pn, p, n);

    if (mpz_cmp(x, pn) >= 0)
      goto fail;

    mpz_add(x, x, n);
    mpz_mod(x, x, p);
  }

  if (!ecc_point_set_x(&r2, x, sign))
    goto fail;

  if (!mpz_invert(ri, signature->r, n))
    goto fail;

  mpz_sub(s1, n, m);
  mpz_mul(s1, s1, ri);
  mpz_mod(s1, s1, n);

  mpz_mul(s2, signature->s, ri);
  mpz_mod(s2, s2, n);

  ecc_scalar_set(&s1_, s1);
  ecc_scalar_set(&s2_, s2);

  ecc_point_mul_g(&lhs, &s1_);
  ecc_point_mul(&rhs, &s2_, &r2);

  if (!ecc_point_add(&Q, &lhs, &rhs))
    goto fail;

  ecc_point_encode(out, out_len, &Q, compress);
  result = 1;
fail:
  mpz_clear(m);
  mpz_clear(x);
  mpz_clear(pn);
  mpz_clear(ri);
  mpz_clear(s1);
  mpz_clear(s2);
  ecc_point_clear(&r2);
  ecc_point_clear(&lhs);
  ecc_point_clear(&rhs);
  ecc_point_clear(&Q);
  ecc_scalar_clear(&s1_);
  ecc_scalar_clear(&s2_);
  return result;
}

int
bcrypto_ecdsa_recover(int type,
                      uint8_t *out,
                      size_t *out_len,
                      const uint8_t *msg,
                      size_t msg_len,
                      const uint8_t *sig,
                      int param,
                      int compress) {
  int result = 0;
  size_t size = ecc_scalar_length(type);
  struct dsa_signature signature;

  if (size == 0)
    return 0;

  dsa_signature_init(&signature);
  bcrypto_dsa_rs2sig(&signature, sig, size);

  if (!bcrypto_ecdsa_recover_inner(type, out, out_len,
                                   msg, msg_len, &signature,
                                   param, compress)) {
    goto fail;
  }

  result = 1;
fail:
  dsa_signature_clear(&signature);
  return result;
}

int
bcrypto_ecdsa_recover_der(int type,
                          uint8_t *out,
                          size_t *out_len,
                          const uint8_t *msg,
                          size_t msg_len,
                          const uint8_t *sig,
                          size_t sig_len,
                          int param,
                          int compress) {
  int result = 0;
  size_t size = ecc_scalar_length(type);
  struct dsa_signature signature;

  if (size == 0)
    return 0;

  dsa_signature_init(&signature);

  if (sig_len == 0)
    goto fail;

  if (!bcrypto_dsa_der2sig(&signature, sig, sig_len, size))
    goto fail;

  if (!bcrypto_ecdsa_recover_inner(type, out, out_len,
                                   msg, msg_len, &signature,
                                   param, compress)) {
    goto fail;
  }

  result = 1;
fail:
  dsa_signature_clear(&signature);
  return result;
}

int
bcrypto_ecdsa_derive(int type,
                     uint8_t *out,
                     size_t *out_len,
                     const uint8_t *pub,
                     size_t pub_len,
                     const uint8_t *key,
                     int compress) {
  return bcrypto_ecdsa_pubkey_tweak_mul(type, out, out_len,
                                        pub, pub_len, key,
                                        compress);
}

static int
schnorr_hash_type(int type) {
  switch (type) {
    case BCRYPTO_CURVE_P192:
    case BCRYPTO_CURVE_P224:
    case BCRYPTO_CURVE_P256:
      return BCRYPTO_HASH_SHA256;
    case BCRYPTO_CURVE_P384:
      return BCRYPTO_HASH_SHA384;
    case BCRYPTO_CURVE_P521:
      return BCRYPTO_HASH_SHA512;
  }
  return -1;
}

static const struct nettle_hash *
schnorr_hash_get(int type) {
  return bcrypto_hash_get(schnorr_hash_type(type));
}

static void
schnorr_hash_am(int type,
                const struct ecc_curve *ecc,
                mp_limb_t *out,
                const struct ecc_scalar *a,
                const uint8_t *msg) {
  const struct nettle_hash *hash = schnorr_hash_get(type);
  size_t bytes = ((size_t)ecc->p.bit_size + 7) / 8;
  mp_size_t size = ecc->p.size;
  uint8_t hraw[BCRYPTO_HASH_MAX_SIZE];
  uint8_t araw[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];
  uint8_t state[BCRYPTO_HASH_MAX_CONTEXT_SIZE];
  mpz_t n, d, k;

  mpz_roinit_n(n, ecc->q.m, size);
  mpz_roinit_n(d, &a->p[0], size);
  mpz_init(k);

  ecc_mpz_pad(&araw[0], bytes, d);

  assert(hash != NULL);

  hash->init(state);
  hash->update(state, bytes, araw);
  hash->update(state, 32, msg);
  hash->digest(state, hash->digest_size, &hraw[0]);

  ecc_mpz_import(k, &hraw[0], hash->digest_size);
  mpz_mod(k, k, n);
  mpz_limbs_copy(out, k, size);
  mpz_clear(k);
}

static void
schnorr_hash_ram(int type,
                 const struct ecc_curve *ecc,
                 mp_limb_t *out,
                 const mpz_t r,
                 const struct ecc_point *A,
                 const uint8_t *msg) {
  const struct nettle_hash *hash = schnorr_hash_get(type);
  size_t bytes = ((size_t)ecc->p.bit_size + 7) / 8;
  mp_size_t size = ecc->p.size;
  uint8_t hraw[BCRYPTO_HASH_MAX_SIZE];
  uint8_t rraw[BCRYPTO_ECDSA_MAX_FIELD_SIZE];
  uint8_t araw[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  uint8_t state[BCRYPTO_HASH_MAX_CONTEXT_SIZE];
  mpz_t n, x, y, e;

  mpz_roinit_n(n, ecc->q.m, size);
  mpz_roinit_n(x, &A->p[0], size);
  mpz_roinit_n(y, &A->p[size], size);
  mpz_init(e);

  ecc_mpz_pad(&rraw[0], bytes, r);

  araw[0] = 0x02 | (mpz_odd_p(y) != 0);
  ecc_mpz_pad(&araw[1], bytes, x);

  assert(hash != NULL);

  hash->init(state);
  hash->update(state, bytes, rraw);
  hash->update(state, 1 + bytes, araw);
  hash->update(state, 32, msg);
  hash->digest(state, hash->digest_size, &hraw[0]);

  ecc_mpz_import(e, &hraw[0], hash->digest_size);
  mpz_mod(e, e, n);
  mpz_limbs_copy(out, e, size);
  mpz_clear(e);
}

static int
schnorr_sign(int type,
             const struct ecc_scalar *key,
             const uint8_t *msg,
             struct dsa_signature *signature) {
  const struct ecc_curve *ecc = key->ecc;
  mp_size_t size = ecc->p.size;
  mpz_t p, n, x, y, s;
  struct ecc_point R, A;
  struct ecc_scalar k, e;
  mp_limb_t S[ECC_MAX_SIZE * 2];
  int result = 0;

  mpz_roinit_n(p, ecc->p.m, size);
  mpz_roinit_n(n, ecc->q.m, size);

  ecc_point_init(&R, ecc);
  ecc_point_init(&A, ecc);
  ecc_scalar_init(&k, ecc);
  ecc_scalar_init(&e, ecc);

  // Let k' = int(hash(bytes(d) || m)) mod n
  schnorr_hash_am(type, ecc, k.p, key, msg);

  // Fail if k' = 0.
  if (mpn_zero_p(&k.p[0], size))
    goto fail;

  // Let R = k'*G.
  ecc_point_mul_g(&R, &k);

  // Encode d*G.
  ecc_point_mul_g(&A, key);

  // Let e = int(hash(bytes(x(R)) || bytes(d*G) || m)) mod n.
  mpz_roinit_n(x, R.p, size);
  schnorr_hash_ram(type, ecc, e.p, x, &A, msg);

  // Let k = k' if jacobi(y(R)) = 1, otherwise let k = n - k'.
  mpz_roinit_n(y, &R.p[size], size);

  if (bmpz_jacobi(y, p) != 1)
    ecc_mod_sub(&ecc->q, k.p, ecc->q.m, k.p);

  // Let S = k + e*d mod n.
  ecc_mod_mul(&ecc->q, S, e.p, key->p);
  ecc_mod_add(&ecc->q, S, k.p, S);

  mpz_roinit_n(s, S, size);

  mpz_set(signature->r, x);
  mpz_set(signature->s, s);

  result = 1;
fail:
  ecc_point_clear(&R);
  ecc_point_clear(&A);
  ecc_scalar_clear(&k);
  ecc_scalar_clear(&e);
  return result;
}

static int
schnorr_verify(int type,
               const struct ecc_point *pub,
               const uint8_t *msg,
               const struct dsa_signature *signature) {
  const struct ecc_curve *ecc = pub->ecc;
  mp_size_t size = ecc->p.size;
  mpz_t p, n, yz;
  mp_limb_t *limbs = NULL;
  mp_limb_t *Rx, *S, *A, *e, *R, *scratch;
  int result = 0;

  mpz_roinit_n(p, ecc->p.m, size);
  mpz_roinit_n(n, ecc->q.m, size);

  assert(ECC_MUL_ADD_ITCH(size) >= ECC_J_TO_A_ITCH(size));

  limbs = gmp_alloc_limbs(size * 6 + ECC_MUL_ADD_ITCH(size));

  if (limbs == NULL)
    goto fail;

  Rx = &limbs[0 * size];
  S = &limbs[1 * size];
  A = pub->p;
  e = &limbs[2 * size];
  R = &limbs[3 * size];
  scratch = &limbs[size * 6];

  // Let r = int(sig[0:32]); fail if r >= p.
  if (mpz_cmp(signature->r, p) >= 0)
    goto fail;

  // Let s = int(sig[32:64]); fail if s >= n.
  if (mpz_cmp(signature->s, n) >= 0)
    goto fail;

  mpz_limbs_copy(Rx, signature->r, size);
  mpz_limbs_copy(S, signature->s, size);

  // Let e = int(hash(bytes(r) || bytes(P) || m)) mod n.
  schnorr_hash_ram(type, ecc, e, signature->r, pub, msg);

  /* Let R = s*G - e*P. */
  ecc_mod_sub(&ecc->q, e, ecc->q.m, e);
  ecc_mul_add(ecc, R, NULL, S, A, e, scratch);

  /* Check for point at infinity. */
  if (mpn_zero_p(&R[2 * size], size))
    goto fail;

  /* Not sure how to get field elements out of redc yet. */
  if (ecc->use_redc) {
    /* Affinize. */
    ecc_j_to_a(ecc, 0, R, R, scratch);

    /* Check for quadratic residue. */
    mpz_roinit_n(yz, &R[size], size);

    if (bmpz_jacobi(yz, p) != 1)
      goto fail;

    /* Check `x(R) == r`. */
    if (mpn_cmp(&R[0], Rx, size) != 0)
      goto fail;
  } else {
    /* Check for quadratic residue in the jacobian space. */
    /* Optimized as `jacobi(y(R) * z(R)) == 1`. */
    ecc_mod_mul(&ecc->p, scratch, &R[size], &R[size * 2]);

    mpz_roinit_n(yz, scratch, size);

    if (bmpz_jacobi(yz, p) != 1)
      goto fail;

    /* Check `x(R) == r` in the jacobian space. */
    /* Optimized as `x(R) == r * z(R)^2 mod p`. */
    ecc_mod_sqr(&ecc->p, scratch, &R[size * 2]);
    ecc_mod_mul(&ecc->p, scratch + size, Rx, scratch); /* Can be the same? */

    if (mpn_cmp(&R[0], scratch + size, size) != 0)
      goto fail;
  }

  result = 1;
fail:
  if (limbs != NULL)
    gmp_free_limbs(limbs, size * 6 * ECC_MUL_ADD_ITCH(size));

  return result;
}

int
bcrypto_schnorr_sign(int type,
                     uint8_t *out,
                     const uint8_t *msg,
                     const uint8_t *key) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  size_t size = ecc_scalar_length(type);
  struct ecc_scalar s;
  struct dsa_signature signature;

  if (ecc == NULL)
    return 0;

  ecc_scalar_init(&s, ecc);
  dsa_signature_init(&signature);

  if (!ecc_scalar_decode(&s, key))
    goto fail;

  schnorr_sign(type, &s, msg, &signature);

  bcrypto_dsa_sig2rs(out, &signature, size);

  result = 1;
fail:
  ecc_scalar_clear(&s);
  dsa_signature_clear(&signature);
  return result;
}

int
bcrypto_schnorr_verify(int type,
                       const uint8_t *msg,
                       const uint8_t *sig,
                       const uint8_t *key,
                       size_t key_len) {
  int result = 0;
  const struct ecc_curve *ecc = ecc_get_curve(type);
  size_t size = ecc_scalar_length(type);
  struct ecc_point p;
  struct dsa_signature signature;

  if (ecc == NULL)
    return 0;

  ecc_point_init(&p, ecc);
  dsa_signature_init(&signature);

  if (!ecc_point_decode(&p, key, key_len))
    goto fail;

  bcrypto_dsa_rs2sig(&signature, sig, size);

  if (!schnorr_verify(type, &p, msg, &signature))
    goto fail;

  result = 1;
fail:
  ecc_point_clear(&p);
  dsa_signature_clear(&signature);
  return result;
}

int
bcrypto_schnorr_batch_verify(int type,
                             const uint8_t **msgs,
                             const uint8_t **sigs,
                             const uint8_t **keys,
                             size_t *key_lens,
                             size_t length) {
  size_t i = 0;

  // Todo: real batch verification.
  for (; i < length; i++) {
    if (!bcrypto_schnorr_verify(type, msgs[i], sigs[i], keys[i], key_lens[i]))
      return 0;
  }

  return 1;
}
