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

static unsigned int
secp256k1_bytes32_le(const unsigned char *a, const unsigned char *b) {
  int eq = ~0;
  int lt = 0;
  size_t shift = sizeof(int) * 8 - 1;
  int i;

  for (i = 0; i < 32; i++) {
    int x = (int)a[i];
    int y = (int)b[i];

    lt = (~eq & lt) | (eq & ((x - y) >> shift));
    eq = eq & (((x ^ y) - 1) >> shift);
  }

  return (eq | lt) & 1;
}

static int
secp256k1_fe_is_neg(const secp256k1_fe *fe) {
  static const unsigned char fq2[32] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xfe, 0x17
  };

  unsigned char check[32];
  secp256k1_fe u;

  u = *fe;
  secp256k1_fe_normalize(&u);
  secp256k1_fe_get_b32(check, &u);
  secp256k1_fe_clear(&u);

  return secp256k1_bytes32_le(check, fq2) ^ 1;
}

static void
shallue_van_de_woestijne(secp256k1_ge *ge, const secp256k1_fe *u) {
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
  secp256k1_fe alphain, betain, gammain, y1, y2, y3;
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

  secp256k1_fe_sqr(&alphain, &x1); /* mag 1 */
  secp256k1_fe_mul(&alphain, &alphain, &x1); /* mag 1 */
  secp256k1_fe_add(&alphain, &b); /* mag 2 */
  secp256k1_fe_sqr(&betain, &x2); /* mag 1 */
  secp256k1_fe_mul(&betain, &betain, &x2); /* mag 1 */
  secp256k1_fe_add(&betain, &b); /* mag 2 */
  secp256k1_fe_sqr(&gammain, &x3); /* mag 1 */
  secp256k1_fe_mul(&gammain, &gammain, &x3); /* mag 1 */
  secp256k1_fe_add(&gammain, &b); /* mag 2 */

  alphaquad = secp256k1_fe_sqrt(&y1, &alphain);
  betaquad = secp256k1_fe_sqrt(&y2, &betain);
  secp256k1_fe_sqrt(&y3, &gammain);

  secp256k1_fe_cmov(&x1, &x2, (!alphaquad) & betaquad);
  secp256k1_fe_cmov(&y1, &y2, (!alphaquad) & betaquad);
  secp256k1_fe_cmov(&x1, &x3, (!alphaquad) & !betaquad);
  secp256k1_fe_cmov(&y1, &y3, (!alphaquad) & !betaquad);

  secp256k1_ge_set_xy(ge, &x1, &y1);

  secp256k1_fe_negate(&tmp, &ge->y, 1);
  secp256k1_fe_cmov(&ge->y, &tmp,
    secp256k1_fe_is_neg(&ge->y) ^ secp256k1_fe_is_neg(u));
}

static int
shallue_van_de_woestijne_invert(secp256k1_fe* u,
                                const secp256k1_ge *ge,
                                unsigned int hint) {
  static const secp256k1_fe c = SECP256K1_FE_CONST(0x0a2d2ba9, 0x3507f1df,
                                                   0x233770c2, 0xa797962c,
                                                   0xc61f6d15, 0xda14ecd4,
                                                   0x7d8d27ae, 0x1cd5f852);

  static const secp256k1_fe i2 = SECP256K1_FE_CONST(0x7fffffff, 0xffffffff,
                                                    0xffffffff, 0xffffffff,
                                                    0xffffffff, 0xffffffff,
                                                    0xffffffff, 0x7ffffe18);

  static const secp256k1_fe one = SECP256K1_FE_CONST(0, 0, 0, 0,
                                                     0, 0, 0, 1);

  secp256k1_fe x, y;
  secp256k1_fe c1, c2, den, den1, den2;
  secp256k1_fe u1, u2, u3, u4, t0, t1, t;
  secp256k1_ge x1, x2, x3, x4;
  int s0, s1, s2, s3, s4;

  /*
   * Map:
   *
   *   t = sqrt(6 * (2 * b - 1) * x + 9 * x^2 - 12 * b - 3) / 2
   *   u1 = +-sqrt(((b + 1) * (c - 2 * x - 1) / (c + 2 * x + 1))
   *   u2 = +-sqrt(((b + 1) * (c + 2 * x + 1) / (c - 2 * x - 1))
   *   u3 = +-sqrt(-b - (3 * x) / 2 + (1 / 2) +- t)
   */

  if (secp256k1_ge_is_infinity(ge))
    return 0;

  x = ge->x;
  y = ge->y;

  secp256k1_fe_normalize(&x);
  secp256k1_fe_normalize(&y);

  /* t = 6 * (2 * b - 1) * x */
  secp256k1_fe_set_int(&t0, 78);
  secp256k1_fe_mul(&t, &t0, &x);

  /* t += 9 * x^2 */
  secp256k1_fe_sqr(&t0, &x);
  secp256k1_fe_mul_int(&t0, 9);
  secp256k1_fe_add(&t, &t0);

  /* t -= 12 * b */
  secp256k1_fe_set_int(&t0, 84);
  secp256k1_fe_negate(&t0, &t0, 1);
  secp256k1_fe_add(&t, &t0);

  /* t -= 3 */
  secp256k1_fe_set_int(&t0, 3);
  secp256k1_fe_negate(&t0, &t0, 1);
  secp256k1_fe_add(&t, &t0);

  /* t = sqrt(t) / 2 */
  s0 = secp256k1_fe_sqrt(&t0, &t);
  secp256k1_fe_mul(&t, &t0, &i2);

  /* t0 = x * 2 + 1 */
  t0 = x;
  secp256k1_fe_mul_int(&t0, 2);
  secp256k1_fe_add(&t0, &one);

  /* c2 = c + t0 */
  c2 = c;
  secp256k1_fe_add(&c2, &t0);

  /* c1 = c - t0 */
  c1 = c;
  secp256k1_fe_negate(&t0, &t0, 1);
  secp256k1_fe_add(&c1, &t0);

  /* den = 1 / (c1 * c2) */
  secp256k1_fe_mul(&den, &c1, &c2);
  secp256k1_fe_inv(&den, &den);

  /* den1 = den * c1 */
  secp256k1_fe_mul(&den1, &den, &c1);

  /* den2 = den * c2 */
  secp256k1_fe_mul(&den2, &den, &c2);

  /* c1 *= b + 1 */
  secp256k1_fe_mul_int(&c1, 8);

  /* c2 *= b + 1 */
  secp256k1_fe_mul_int(&c2, 8);

  /* u1 = c1 / c2 */
  secp256k1_fe_mul(&u1, &c1, &den1);

  /* u2 = c2 / c1 */
  secp256k1_fe_mul(&u2, &c2, &den2);

  /* u1 = sqrt(u1) */
  t0 = u1;
  s1 = secp256k1_fe_sqrt(&u1, &t0);

  /* u2 = sqrt(u2) */
  t0 = u2;
  s2 = secp256k1_fe_sqrt(&u2, &t0);

  /* t0 = -b */
  secp256k1_fe_set_int(&t0, 7);
  secp256k1_fe_negate(&t0, &t0, 1);

  /* t1 = (3 * x) / 2 */
  secp256k1_fe_mul(&t1, &x, &i2);
  secp256k1_fe_mul_int(&t1, 3);

  /* t0 = t0 - t1 + i2 */
  secp256k1_fe_negate(&t1, &t1, 1);
  secp256k1_fe_add(&t0, &t1);
  secp256k1_fe_add(&t0, &i2);

  /* t1 = t0 */
  t1 = t0;

  /* t0 += t */
  secp256k1_fe_add(&t0, &t);

  /* t1 -= t */
  secp256k1_fe_negate(&t, &t, 1);
  secp256k1_fe_add(&t1, &t);

  /* u3 = sqrt(t0) */
  s3 = secp256k1_fe_sqrt(&u3, &t0);

  /* u3 = sqrt(t1) */
  s4 = secp256k1_fe_sqrt(&u4, &t1);

  shallue_van_de_woestijne(&x1, &u1);
  shallue_van_de_woestijne(&x2, &u2);
  shallue_van_de_woestijne(&x3, &u3);
  shallue_van_de_woestijne(&x4, &u4);

  const int S[4] = {
    s1 & secp256k1_fe_equal(&x1.x, &x),
    s2 & secp256k1_fe_equal(&x2.x, &x),
    s0 & s3 & secp256k1_fe_equal(&x3.x, &x),
    s0 & s4 & secp256k1_fe_equal(&x4.x, &x)
  };

  secp256k1_fe_cmov(u, &u1, (hint & 3) == 0);
  secp256k1_fe_cmov(u, &u2, (hint & 3) == 1);
  secp256k1_fe_cmov(u, &u3, (hint & 3) == 2);
  secp256k1_fe_cmov(u, &u4, (hint & 3) == 3);

  secp256k1_fe_negate(&t0, u, 1);
  secp256k1_fe_cmov(u, &t0,
    secp256k1_fe_is_neg(u) ^ secp256k1_fe_is_neg(&y));

  return S[hint & 3] != 0;
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
  secp256k1_rfc6979_hmac_sha256_generate(rng, raw, 32);
  secp256k1_fe_set_b32(fe, raw);
}

static unsigned int
secp256k1_random_int(secp256k1_rfc6979_hmac_sha256_t *rng) {
  unsigned char raw[4];
  secp256k1_rfc6979_hmac_sha256_generate(rng, raw, 4);
  return ((unsigned int)raw[0] << 24)
       | ((unsigned int)raw[1] << 16)
       | ((unsigned int)raw[2] << 8)
       | ((unsigned int)raw[3] << 0);
}

static int
secp256k1_pubkey_to_hash(unsigned char *bytes64,
                         const secp256k1_pubkey *pubkey,
                         const unsigned char *seed32) {
  secp256k1_rfc6979_hmac_sha256_t rng;
  secp256k1_ge p, p1, p2;
  secp256k1_gej j, r;
  secp256k1_fe u1, u2;
  unsigned int hint;

  if (!secp256k1_pubkey_unstore(&p, pubkey))
    return 0;

  secp256k1_gej_set_ge(&j, &p);
  secp256k1_rfc6979_hmac_sha256_initialize(&rng, seed32, 32);

  for (;;) {
    secp256k1_fe_random(&u1, &rng);
    shallue_van_de_woestijne(&p1, &u1);

    /* p2 = p - p1 */
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
