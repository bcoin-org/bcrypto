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
   * coeffiecient of the curve, but
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

static int
ecc_point_add(struct ecc_point *r,
              const struct ecc_point *a,
              const struct ecc_point *b) {
  int result = 0;
  const struct ecc_curve *ecc = r->ecc;
  mp_size_t size = ecc->p.size;
  mp_limb_t *limbs, *j1, *j2, *scratch;

  /* Space for 2 jacobian points and an addition. */
  limbs = gmp_alloc_limbs(6 * size + ECC_ADD_JJJ_ITCH(size));
  assert(limbs != NULL);

  /* Setup points and scratch. */
  j1 = &limbs[0];
  j2 = &limbs[3 * size];
  scratch = &limbs[6 * size];

  /* O + P = P */
  if (mpn_zero_p(a->p, size * 2)) {
    result = 1;
    if (r != b)
      mpn_copyi(r->p, b->p, size * 2);
    goto fail;
  }

  /* P + O = P */
  if (mpn_zero_p(b->p, size * 2)) {
    result = 1;
    if (r != a)
      mpn_copyi(r->p, a->p, size * 2);
    goto fail;
  }

  ecc_a_to_j(ecc, j1, a->p);
  ecc_a_to_j(ecc, j2, b->p);

  if (mpn_cmp(j1, j2, size * 3) == 0) {
    /* P + P = 2P */
    assert(ECC_ADD_JJJ_ITCH(size) >= ECC_DUP_JJ_ITCH(size));
    ecc_dup_jj(ecc, j1, j1, scratch);
  } else {
    ecc_add_jjj(ecc, j1, j1, j2, scratch);
  }

  /* Check for infinity. */
  if (mpn_zero_p(j1 + 2 * size, size))
    goto fail;

  /* Reuse scratch. */
  assert(ECC_ADD_JJJ_ITCH(size) >= ECC_J_TO_A_ITCH(size));
  ecc_j_to_a(ecc, 0, r->p, j1, scratch);

  result = 1;
fail:
  gmp_free_limbs(limbs, 6 * size + ECC_ADD_JJJ_ITCH(size));
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
  assert(r.p != NULL);

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

  scratch = gmp_alloc_limbs(2 * ecc->p.size + ecc->q.invert_itch);
  assert(scratch != NULL);

  ecc_scalar_init(&s, ecc);

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
