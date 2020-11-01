/*!
 * p521.h - p521 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#if defined(TORSION_HAVE_INT128)
typedef uint64_t p521_fe_word_t;
#define P521_FIELD_WORDS 9
#include "p521_64.h"
#else
typedef uint32_t p521_fe_word_t;
#define P521_FIELD_WORDS 19
#include "p521_32.h"
#endif

typedef p521_fe_word_t p521_fe_t[P521_FIELD_WORDS];

#define p521_fe_add fiat_p521_add
#define p521_fe_sub fiat_p521_sub
#define p521_fe_neg fiat_p521_opp
#define p521_fe_mul fiat_p521_carry_mul
#define p521_fe_sqr fiat_p521_carry_square

static void
p521_fe_set(p521_fe_t r, const p521_fe_t x) {
  r[0] = x[0];
  r[1] = x[1];
  r[2] = x[2];
  r[3] = x[3];
  r[4] = x[4];
  r[5] = x[5];
  r[6] = x[6];
  r[7] = x[7];
  r[8] = x[8];
#if P521_FIELD_WORDS == 19
  r[9] = x[9];
  r[10] = x[10];
  r[11] = x[11];
  r[12] = x[12];
  r[13] = x[13];
  r[14] = x[14];
  r[15] = x[15];
  r[16] = x[16];
  r[17] = x[17];
  r[18] = x[18];
#endif
}

static int
p521_fe_equal(const p521_fe_t x, const p521_fe_t y) {
  uint32_t z = 0;
  uint8_t u[66];
  uint8_t v[66];
  int i;

  fiat_p521_to_bytes(u, x);
  fiat_p521_to_bytes(v, y);

  for (i = 0; i < 66; i++)
    z |= (uint32_t)u[i] ^ (uint32_t)v[i];

  return (z - 1) >> 31;
}

static void
p521_fe_sqrn(p521_fe_t r, const p521_fe_t x, int n) {
  int i;

  p521_fe_sqr(r, x);

  for (i = 1; i < n; i++)
    p521_fe_sqr(r, r);
}

static void
p521_fe_pow_core(p521_fe_t r, const p521_fe_t x1) {
  /* Exponent: 2^519 - 1 */
  /* Bits: 519x1 */
  p521_fe_t t1, t2, t3;

  /* x2 = x1^(2^1) * x1 */
  p521_fe_sqr(t1, x1);
  p521_fe_mul(t1, t1, x1);

  /* x3 = x2^(2^1) * x1 */
  p521_fe_sqr(t1, t1);
  p521_fe_mul(t1, t1, x1);

  /* x6 = x3^(2^3) * x3 */
  p521_fe_sqrn(t2, t1, 3);
  p521_fe_mul(t2, t2, t1);

  /* x7 = x6^(2^1) * x1 */
  p521_fe_sqr(t1, t2);
  p521_fe_mul(t1, t1, x1);

  /* x8 = x7^(2^1) * x1 */
  p521_fe_sqr(t2, t1);
  p521_fe_mul(t2, t2, x1);

  /* x16 = x8^(2^8) * x8 */
  p521_fe_sqrn(t3, t2, 8);
  p521_fe_mul(t3, t3, t2);

  /* x32 = x16^(2^16) * x16 */
  p521_fe_sqrn(t2, t3, 16);
  p521_fe_mul(t2, t2, t3);

  /* x64 = x32^(2^32) * x32 */
  p521_fe_sqrn(t3, t2, 32);
  p521_fe_mul(t3, t3, t2);

  /* x128 = x64^(2^64) * x64 */
  p521_fe_sqrn(t2, t3, 64);
  p521_fe_mul(t2, t2, t3);

  /* x256 = x128^(2^128) * x128 */
  p521_fe_sqrn(t3, t2, 128);
  p521_fe_mul(t3, t3, t2);

  /* x512 = x256^(2^256) * x256 */
  p521_fe_sqrn(r, t3, 256);
  p521_fe_mul(r, r, t3);

  /* x519 = x512^(2^7) * x7 */
  p521_fe_sqrn(r, r, 7);
  p521_fe_mul(r, r, t1);
}

static void
p521_fe_pow_pm3d4(p521_fe_t r, const p521_fe_t x) {
  /* Exponent: 2^519 - 1 */
  /* Bits: 519x1 */

  /* r = x^(2^519 - 1) */
  p521_fe_pow_core(r, x);
}

static void
p521_fe_invert(p521_fe_t r, const p521_fe_t x) {
  /* Exponent: p - 2 */
  /* Bits: 519x1 1x0 1x1 */
  p521_fe_t x1;

  /* x1 = x */
  p521_fe_set(x1, x);

  /* r = x1^(2^519 - 1) */
  p521_fe_pow_core(r, x1);

  /* r = r^(2^1) */
  p521_fe_sqr(r, r);

  /* r = r^(2^1) * x1 */
  p521_fe_sqr(r, r);
  p521_fe_mul(r, r, x1);
}

static int
p521_fe_sqrt(p521_fe_t r, const p521_fe_t x) {
  /* Exponent: (p + 1) / 4 */
  /* Bits: 1x1 519x0 */
  p521_fe_t x1, c;

  /* x1 = x */
  p521_fe_set(x1, x);

  /* r = x1^(2^519) */
  p521_fe_sqrn(r, x1, 519);

  /* r^2 == x1 */
  p521_fe_sqr(c, r);

  return p521_fe_equal(c, x1);
}

static int
p521_fe_isqrt(p521_fe_t r, const p521_fe_t u, const p521_fe_t v) {
  p521_fe_t t, x, c;
  int ret;

  /* x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p */
  p521_fe_sqr(t, u);       /* u^2 */
  p521_fe_mul(c, t, u);    /* u^3 */
  p521_fe_mul(t, t, c);    /* u^5 */
  p521_fe_sqr(x, v);       /* v^2 */
  p521_fe_mul(x, x, v);    /* v^3 */
  p521_fe_mul(x, x, t);    /* v^3 * u^5 */
  p521_fe_pow_pm3d4(x, x); /* (v^3 * u^5)^((p - 3) / 4) */
  p521_fe_mul(x, x, v);    /* (v^3 * u^5)^((p - 3) / 4) * v */
  p521_fe_mul(x, x, c);    /* (v^3 * u^5)^((p - 3) / 4) * v * u^3 */

  /* x^2 * v == u */
  p521_fe_sqr(c, x);
  p521_fe_mul(c, c, v);

  ret = p521_fe_equal(c, u);

  p521_fe_set(r, x);

  return ret;
}
