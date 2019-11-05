/*
 * elligator.h - elligator for libsecp256k1
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on ElementsProject/secp256k1-zkp:
 *   Copyright (c) 2013, Pieter Wuille
 *   https://github.com/ElementsProject/secp256k1-zkp
 *
 * This module implements the Elligator Squared protocol for secp256k1.
 *
 * See: Elligator Squared.
 *   Mehdi Tibouchi.
 *   Algorithm 1, Page 8, Section 3.3.
 *   https://eprint.iacr.org/2014/043.pdf
 *
 * Also: Indifferentiable Hashing to Barreto-Naehrig Curves.
 *   Pierre-Alain Fouque, Mehdi Tibouchi.
 *   Page 8, Section 3.
 *   Page 15, Section 6, Algorithm 1.
 *   https://www.di.ens.fr/~fouque/pub/latincrypt12.pdf
 */

static void
secp256k1_fe_pow_pm3d4(secp256k1_fe *r, const secp256k1_fe *a) {
  /* Compute a^((p - 3) / 4) with sliding window. Could be improved. */
  secp256k1_fe w2, w4, w11, w12, w14, w15;
  int i;

  secp256k1_fe_sqr(&w2, a);
  secp256k1_fe_sqr(&w4, &w2);
  secp256k1_fe_sqr(&w11, &w4);
  secp256k1_fe_mul(&w11, &w11, &w2);
  secp256k1_fe_mul(&w11, &w11, a);
  secp256k1_fe_mul(&w12, &w11, a);
  secp256k1_fe_mul(&w14, &w12, &w2);
  secp256k1_fe_mul(&w15, &w11, &w4);

  *r = w15;
  secp256k1_fe_sqr(r, r);
  secp256k1_fe_sqr(r, r);
  secp256k1_fe_sqr(r, r);
  secp256k1_fe_sqr(r, r);

  for (i = 0; i < 54; i++) {
    secp256k1_fe_mul(r, r, &w15);
    secp256k1_fe_sqr(r, r);
    secp256k1_fe_sqr(r, r);
    secp256k1_fe_sqr(r, r);
    secp256k1_fe_sqr(r, r);
  }

  secp256k1_fe_mul(r, r, &w14);
  secp256k1_fe_sqr(r, r);
  secp256k1_fe_sqr(r, r);
  secp256k1_fe_sqr(r, r);
  secp256k1_fe_sqr(r, r);

  for (i = 0; i < 5; i++) {
    secp256k1_fe_mul(r, r, &w15);
    secp256k1_fe_sqr(r, r);
    secp256k1_fe_sqr(r, r);
    secp256k1_fe_sqr(r, r);
    secp256k1_fe_sqr(r, r);
  }

  secp256k1_fe_mul(r, r, &w12);
  secp256k1_fe_sqr(r, r);
  secp256k1_fe_sqr(r, r);
  secp256k1_fe_sqr(r, r);
  secp256k1_fe_sqr(r, r);
  secp256k1_fe_sqr(r, r);
  secp256k1_fe_sqr(r, r);

  secp256k1_fe_mul(r, r, &w11);
}

static int
secp256k1_fe_isqrt(secp256k1_fe *r,
                   const secp256k1_fe *u,
                   const secp256k1_fe *v) {
  /* x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p */
  secp256k1_fe u2, u3, u5, v3, p, x, c;
  secp256k1_fe_sqr(&u2, u);
  secp256k1_fe_mul(&u3, &u2, u);
  secp256k1_fe_mul(&u5, &u3, &u2);
  secp256k1_fe_sqr(&v3, v);
  secp256k1_fe_mul(&v3, &v3, v);
  secp256k1_fe_mul(&p, &u5, &v3);
  secp256k1_fe_pow_pm3d4(&p, &p);
  secp256k1_fe_mul(&x, &u3, v);
  secp256k1_fe_mul(&x, &x, &p);
  secp256k1_fe_sqr(&c, &x);
  secp256k1_fe_mul(&c, &c, v);
  *r = x;
  return secp256k1_fe_equal(&c, u);
}

static void
shallue_van_de_woestijne_xy2(secp256k1_fe *x,
                             secp256k1_fe *y,
                             const secp256k1_fe *u) {
  /* Copyright (c) 2016 Andrew Poelstra & Pieter Wuille */

  /*
   * Map:
   *
   *   c = sqrt(-3)
   *   d = (c - 1) / 2
   *   w = c * u / (1 + b + u^2) [with b = 7]
   *   x1 = d - u * w
   *   x2 = -(x1 + 1)
   *   x3 = 1 + 1 / w^2
   *
   * To avoid the 2 divisions, compute the above in numerator/denominator form:
   *
   *   wn = c * u
   *   wd = 1 + 7 + u^2
   *   x1n = d * wd - u * wn
   *   x1d = wd
   *   x2n = -(x1n + wd)
   *   x2d = wd
   *   x3n = wd^2 + c^2 + u^2
   *   x3d = (c * u)^2
   *
   * The joint denominator j = wd * c^2 * u^2, and
   *   1 / x1d = 1/j * c^2 * u^2
   *   1 / x2d = x3d = 1/j * wd
   */

  static const secp256k1_fe c = SECP256K1_FE_CONST(0x0a2d2ba9, 0x3507f1df,
                                                   0x233770c2, 0xa797962c,
                                                   0xc61f6d15, 0xda14ecd4,
                                                   0x7d8d27ae, 0x1cd5f852);

  static const secp256k1_fe d = SECP256K1_FE_CONST(0x851695d4, 0x9a83f8ef,
                                                   0x919bb861, 0x53cbcb16,
                                                   0x630fb68a, 0xed0a766a,
                                                   0x3ec693d6, 0x8e6afa40);

  static const secp256k1_fe b = SECP256K1_FE_CONST(0, 0, 0, 0,
                                                   0, 0, 0, 7);

  static const secp256k1_fe b_plus_one = SECP256K1_FE_CONST(0, 0, 0, 0,
                                                            0, 0, 0, 8);

  secp256k1_fe wn, wd, x1n, x2n, x3n, x3d, jinv, tmp, x1, x2, x3;
  secp256k1_fe y1, y2, y3;
  int alphaquad, betaquad;

  secp256k1_fe_mul(&wn, &c, u); /* mag 1 */
  secp256k1_fe_sqr(&wd, u); /* mag 1 */
  secp256k1_fe_add(&wd, &b_plus_one); /* mag 2 */
  secp256k1_fe_mul(&tmp, u, &wn); /* mag 1 */
  secp256k1_fe_negate(&tmp, &tmp, 1); /* mag 2 */
  secp256k1_fe_mul(&x1n, &d, &wd); /* mag 1 */
  secp256k1_fe_add(&x1n, &tmp); /* mag 3 */
  x2n = x1n; /* mag 3 */
  secp256k1_fe_add(&x2n, &wd); /* mag 5 */
  secp256k1_fe_negate(&x2n, &x2n, 5); /* mag 6 */
  secp256k1_fe_mul(&x3d, &c, u); /* mag 1 */
  secp256k1_fe_sqr(&x3d, &x3d); /* mag 1 */
  secp256k1_fe_sqr(&x3n, &wd); /* mag 1 */
  secp256k1_fe_add(&x3n, &x3d); /* mag 2 */
  secp256k1_fe_mul(&jinv, &x3d, &wd); /* mag 1 */
  secp256k1_fe_inv(&jinv, &jinv); /* mag 1 */
  secp256k1_fe_mul(&x1, &x1n, &x3d); /* mag 1 */
  secp256k1_fe_mul(&x1, &x1, &jinv); /* mag 1 */
  secp256k1_fe_mul(&x2, &x2n, &x3d); /* mag 1 */
  secp256k1_fe_mul(&x2, &x2, &jinv); /* mag 1 */
  secp256k1_fe_mul(&x3, &x3n, &wd); /* mag 1 */
  secp256k1_fe_mul(&x3, &x3, &jinv); /* mag 1 */

  secp256k1_fe_sqr(&y1, &x1); /* mag 1 */
  secp256k1_fe_mul(&y1, &y1, &x1); /* mag 1 */
  secp256k1_fe_add(&y1, &b); /* mag 2 */
  secp256k1_fe_sqr(&y2, &x2); /* mag 1 */
  secp256k1_fe_mul(&y2, &y2, &x2); /* mag 1 */
  secp256k1_fe_add(&y2, &b); /* mag 2 */
  secp256k1_fe_sqr(&y3, &x3); /* mag 1 */
  secp256k1_fe_mul(&y3, &y3, &x3); /* mag 1 */
  secp256k1_fe_add(&y3, &b); /* mag 2 */

  alphaquad = secp256k1_fe_sqrt(&tmp, &y1);
  betaquad = secp256k1_fe_sqrt(&tmp, &y2);

  secp256k1_fe_cmov(&x1, &x2, (!alphaquad) & betaquad);
  secp256k1_fe_cmov(&y1, &y2, (!alphaquad) & betaquad);
  secp256k1_fe_cmov(&x1, &x3, (!alphaquad) & !betaquad);
  secp256k1_fe_cmov(&y1, &y3, (!alphaquad) & !betaquad);

  *x = x1;
  *y = y1;
}

static void
shallue_van_de_woestijne(secp256k1_ge *ge, const secp256k1_fe *u) {
  secp256k1_fe x, y, y2;
  int flip;

  shallue_van_de_woestijne_xy2(&x, &y2, u);
  secp256k1_fe_sqrt(&y, &y2);

  flip = secp256k1_fe_is_odd(&y) ^ secp256k1_fe_is_odd(u);
  secp256k1_fe_negate(&y2, &y, 1);
  secp256k1_fe_cmov(&y, &y2, flip);

  secp256k1_ge_set_xy(ge, &x, &y);
}

static int
shallue_van_de_woestijne_invert(secp256k1_fe* u,
                                const secp256k1_ge *ge,
                                unsigned int hint) {
  size_t shift = sizeof(unsigned int) * 8 - 1;

  static const secp256k1_fe c = SECP256K1_FE_CONST(0x0a2d2ba9, 0x3507f1df,
                                                   0x233770c2, 0xa797962c,
                                                   0xc61f6d15, 0xda14ecd4,
                                                   0x7d8d27ae, 0x1cd5f852);

  static const secp256k1_fe one = SECP256K1_FE_CONST(0, 0, 0, 0,
                                                     0, 0, 0, 1);

  secp256k1_fe x, y, c0, c1, n0, n1, n2, n3, d0, t, tmp;
  unsigned int r = hint & 3;
  unsigned int s0, s1, s2, s3, flip;

  /*
   * Map:
   *
   *   t = sqrt(6 * (2 * b - 1) * x + 9 * x^2 - 12 * b - 3)
   *   u1 = +-sqrt(((b + 1) * (c - 2 * x - 1) / (c + 2 * x + 1))
   *   u2 = +-sqrt(((b + 1) * (c + 2 * x + 1) / (c - 2 * x - 1))
   *   u3 = +-sqrt((2 * -b - (3 * x) + 1 +- t) / 2)
   */

  if (secp256k1_ge_is_infinity(ge))
    return 0;

  x = ge->x;
  y = ge->y;

  secp256k1_fe_normalize(&x);
  secp256k1_fe_normalize(&y);

  /* t = sqrt(6 * (2 * b - 1) * x + 9 * x^2 - 12 * b - 3) */
  secp256k1_fe_set_int(&tmp, 78);
  secp256k1_fe_mul(&t, &tmp, &x);

  secp256k1_fe_sqr(&tmp, &x);
  secp256k1_fe_mul_int(&tmp, 9);
  secp256k1_fe_add(&t, &tmp);

  secp256k1_fe_set_int(&tmp, 84);
  secp256k1_fe_negate(&tmp, &tmp, 1);
  secp256k1_fe_add(&t, &tmp);

  secp256k1_fe_set_int(&tmp, 3);
  secp256k1_fe_negate(&tmp, &tmp, 1);
  secp256k1_fe_add(&t, &tmp);

  s0 = secp256k1_fe_sqrt(&tmp, &t);
  s1 = ((r - 2) >> shift) | s0; /* r < 2 or t is square */
  t = tmp;

  /* c1 = c + 2 * x + 1 */
  c1 = c;
  tmp = x;
  secp256k1_fe_mul_int(&tmp, 2);
  secp256k1_fe_add(&tmp, &one);
  secp256k1_fe_add(&c1, &tmp);

  /* c0 = c - 2 * x - 1 */
  c0 = c;
  secp256k1_fe_negate(&tmp, &tmp, 1);
  secp256k1_fe_add(&c0, &tmp);

  /* n0 = (b + 1) * c0 */
  n0 = c0;
  secp256k1_fe_mul_int(&n0, 8);

  /* n1 = (b + 1) * c1 */
  n1 = c1;
  secp256k1_fe_mul_int(&n1, 8);

  /* n2 = 2 * -b - (3 * x) + 1 + t */
  secp256k1_fe_set_int(&n2, 14);
  secp256k1_fe_negate(&n2, &n2, 1);
  tmp = x;
  secp256k1_fe_mul_int(&tmp, 3);
  secp256k1_fe_negate(&tmp, &tmp, 1);
  secp256k1_fe_add(&n2, &tmp);
  secp256k1_fe_add(&n2, &one);
  n3 = n2;
  secp256k1_fe_add(&n2, &t);

  /* n3 = 2 * -b - (3 * x) + 1 - t */
  secp256k1_fe_negate(&t, &t, 1);
  secp256k1_fe_add(&n3, &t);

  /* d0 = 2 */
  secp256k1_fe_set_int(&d0, 2);

  /* Pick numerator and denominator. */
  secp256k1_fe_cmov(&n0, &n1, ((r ^ 1) - 1) >> shift); /* r = 1 */
  secp256k1_fe_cmov(&n0, &n2, ((r ^ 2) - 1) >> shift); /* r = 2 */
  secp256k1_fe_cmov(&n0, &n3, ((r ^ 3) - 1) >> shift); /* r = 3 */
  secp256k1_fe_cmov(&d0, &c1, ((r ^ 0) - 1) >> shift); /* r = 0 */
  secp256k1_fe_cmov(&d0, &c0, ((r ^ 1) - 1) >> shift); /* r = 1 */

  /* t = sqrt(n0 / d0) */
  s2 = secp256k1_fe_isqrt(&t, &n0, &d0);

  /* (n0, d0) = svdw(t) */
  shallue_van_de_woestijne_xy2(&n0, &d0, &t);
  s3 = secp256k1_fe_equal(&n0, &x);

  /* t = sign(y) * abs(t) */
  flip = secp256k1_fe_is_odd(&t) ^ secp256k1_fe_is_odd(&y);
  secp256k1_fe_negate(&tmp, &t, 1);
  secp256k1_fe_cmov(&t, &tmp, flip);

  *u = t;

  return s1 & s2 & s3;
}

static int
secp256k1_pubkey_unstore(secp256k1_ge *ge, const secp256k1_pubkey *pubkey) {
  if (sizeof(secp256k1_ge_storage) == 64) {
    secp256k1_ge_storage s;
    memcpy(&s, &pubkey->data[0], 64);
    secp256k1_ge_from_storage(ge, &s);
  } else {
    secp256k1_fe x, y;
    secp256k1_fe_set_b32(&x, pubkey->data);
    secp256k1_fe_set_b32(&y, pubkey->data + 32);
    secp256k1_ge_set_xy(ge, &x, &y);
  }
  return 1;
}

static void
secp256k1_pubkey_store(secp256k1_pubkey *pubkey, secp256k1_ge *ge) {
  if (sizeof(secp256k1_ge_storage) == 64) {
    secp256k1_ge_storage s;
    secp256k1_ge_to_storage(&s, ge);
    memcpy(&pubkey->data[0], &s, 64);
  } else {
    VERIFY_CHECK(!secp256k1_ge_is_infinity(ge));
    secp256k1_fe_normalize_var(&ge->x);
    secp256k1_fe_normalize_var(&ge->y);
    secp256k1_fe_get_b32(pubkey->data, &ge->x);
    secp256k1_fe_get_b32(pubkey->data + 32, &ge->y);
  }
}

static void
secp256k1_pubkey_from_uniform(secp256k1_pubkey *pubkey,
                              const unsigned char *bytes32) {
  secp256k1_ge p;
  secp256k1_fe u;

  secp256k1_fe_set_b32(&u, bytes32);
  secp256k1_fe_normalize(&u);

  shallue_van_de_woestijne(&p, &u);

  secp256k1_pubkey_store(pubkey, &p);

  secp256k1_ge_clear(&p);
  secp256k1_fe_clear(&u);
}

static int
secp256k1_pubkey_to_uniform(unsigned char *bytes32,
                            const secp256k1_pubkey *pubkey,
                            unsigned int hint) {
  secp256k1_ge p;
  secp256k1_fe u;

  if (!secp256k1_pubkey_unstore(&p, pubkey))
    return 0;

  if (!shallue_van_de_woestijne_invert(&u, &p, hint)) {
    secp256k1_ge_clear(&p);
    return 0;
  }

  secp256k1_fe_normalize(&u);
  secp256k1_fe_get_b32(bytes32, &u);
  secp256k1_fe_clear(&u);

  return 1;
}

static int
secp256k1_pubkey_from_hash(secp256k1_pubkey *pubkey,
                           const unsigned char *bytes64) {
  secp256k1_gej j, r;
  secp256k1_ge p1, p2;
  secp256k1_fe u1, u2;
  int ret;

  secp256k1_fe_set_b32(&u1, bytes64);
  secp256k1_fe_set_b32(&u2, bytes64 + 32);

  secp256k1_fe_normalize(&u1);
  secp256k1_fe_normalize(&u2);

  shallue_van_de_woestijne(&p1, &u1);
  shallue_van_de_woestijne(&p2, &u2);

  secp256k1_gej_set_ge(&j, &p1);
  secp256k1_gej_add_ge(&r, &j, &p2);
  secp256k1_ge_set_gej(&p1, &r);

  ret = !secp256k1_ge_is_infinity(&p1);

  if (ret)
    secp256k1_pubkey_store(pubkey, &p1);

  secp256k1_gej_clear(&r);
  secp256k1_gej_clear(&j);
  secp256k1_ge_clear(&p1);
  secp256k1_ge_clear(&p2);
  secp256k1_fe_clear(&u1);
  secp256k1_fe_clear(&u2);

  return ret;
}

static void
secp256k1_fe_random(secp256k1_fe *fe, secp256k1_rfc6979_hmac_sha256_t *rng) {
  unsigned char raw[32];

  for (;;) {
    secp256k1_rfc6979_hmac_sha256_generate(rng, raw, 32);

    if (secp256k1_fe_set_b32(fe, raw))
      break;
  }
}

static unsigned int
secp256k1_random_int(secp256k1_rfc6979_hmac_sha256_t *rng) {
  unsigned char raw[2];
  secp256k1_rfc6979_hmac_sha256_generate(rng, raw, 2);
  return ((unsigned int)raw[0] << 8) | (unsigned int)raw[1];
}

static int
secp256k1_pubkey_to_hash(unsigned char *bytes64,
                         const secp256k1_pubkey *pubkey,
                         const unsigned char *seed64) {
  secp256k1_rfc6979_hmac_sha256_t rng;
  secp256k1_ge p, p1, p2;
  secp256k1_gej j, r;
  secp256k1_fe u1, u2;
  unsigned int hint;

  if (!secp256k1_pubkey_unstore(&p, pubkey))
    return 0;

  secp256k1_gej_set_ge(&j, &p);
  secp256k1_rfc6979_hmac_sha256_initialize(&rng, seed64, 64);

  for (;;) {
    secp256k1_fe_random(&u1, &rng);
    shallue_van_de_woestijne(&p1, &u1);
    secp256k1_ge_neg(&p1, &p1);
    secp256k1_gej_add_ge(&r, &j, &p1);
    secp256k1_ge_set_gej(&p2, &r);

    hint = secp256k1_random_int(&rng);

    if (shallue_van_de_woestijne_invert(&u2, &p2, hint))
      break;
  }

  secp256k1_fe_normalize(&u1);
  secp256k1_fe_normalize(&u2);

  secp256k1_fe_get_b32(bytes64, &u1);
  secp256k1_fe_get_b32(bytes64 + 32, &u2);

  secp256k1_rfc6979_hmac_sha256_finalize(&rng);
  secp256k1_ge_clear(&p);
  secp256k1_ge_clear(&p1);
  secp256k1_ge_clear(&p2);
  secp256k1_gej_clear(&j);
  secp256k1_gej_clear(&r);
  secp256k1_fe_clear(&u1);
  secp256k1_fe_clear(&u2);

  return 1;
}
