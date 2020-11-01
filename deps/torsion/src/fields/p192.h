/*!
 * p192.h - p192 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#if defined(TORSION_HAVE_INT128)
typedef uint64_t p192_fe_word_t;
#define P192_FIELD_WORDS 4
#include "p192_64.h"
#else
typedef uint32_t p192_fe_word_t;
#define P192_FIELD_WORDS 9
#include "p192_32.h"
#endif

typedef p192_fe_word_t p192_fe_t[P192_FIELD_WORDS];

#define p192_fe_add fiat_p192_add
#define p192_fe_sub fiat_p192_sub
#define p192_fe_neg fiat_p192_opp
#define p192_fe_mul fiat_p192_carry_mul
#define p192_fe_sqr fiat_p192_carry_square

static void
p192_fe_set(p192_fe_t r, const p192_fe_t x) {
  r[0] = x[0];
  r[1] = x[1];
  r[2] = x[2];
  r[3] = x[3];
#if P192_FIELD_WORDS == 9
  r[4] = x[4];
  r[5] = x[5];
  r[6] = x[6];
  r[7] = x[7];
  r[8] = x[8];
#endif
}

static int
p192_fe_equal(const p192_fe_t x, const p192_fe_t y) {
  uint32_t z = 0;
  uint8_t u[24];
  uint8_t v[24];
  int i;

  fiat_p192_to_bytes(u, x);
  fiat_p192_to_bytes(v, y);

  for (i = 0; i < 24; i++)
    z |= (uint32_t)u[i] ^ (uint32_t)v[i];

  return (z - 1) >> 31;
}

static void
p192_fe_sqrn(p192_fe_t r, const p192_fe_t x, int n) {
  int i;

  p192_fe_sqr(r, x);

  for (i = 1; i < n; i++)
    p192_fe_sqr(r, r);
}

static void
p192_fe_pow_pm3d4(p192_fe_t r, const p192_fe_t x1) {
  /* Exponent: (p - 3) / 4 */
  /* Bits: 127x1 1x0 62x1 */
  p192_fe_t t1, t2, t3, t4;

  /* x2 = x1^(2^1) * x1 */
  p192_fe_sqr(t1, x1);
  p192_fe_mul(t1, t1, x1);

  /* x3 = x2^(2^1) * x1 */
  p192_fe_sqr(t1, t1);
  p192_fe_mul(t1, t1, x1);

  /* x6 = x3^(2^3) * x3 */
  p192_fe_sqrn(t2, t1, 3);
  p192_fe_mul(t2, t2, t1);

  /* x12 = x6^(2^6) * x6 */
  p192_fe_sqrn(t3, t2, 6);
  p192_fe_mul(t3, t3, t2);

  /* x24 = x12^(2^12) * x12 */
  p192_fe_sqrn(t4, t3, 12);
  p192_fe_mul(t4, t4, t3);

  /* x30 = x24^(2^6) * x6 */
  p192_fe_sqrn(t3, t4, 6);
  p192_fe_mul(t3, t3, t2);

  /* x31 = x30^(2^1) * x1 */
  p192_fe_sqr(t3, t3);
  p192_fe_mul(t3, t3, x1);

  /* x62 = x31^(2^31) * x31 */
  p192_fe_sqrn(t4, t3, 31);
  p192_fe_mul(t4, t4, t3);

  /* x124 = x62^(2^62) * x62 */
  p192_fe_sqrn(r, t4, 62);
  p192_fe_mul(r, r, t4);

  /* x127 = x124^(2^3) * x3 */
  p192_fe_sqrn(r, r, 3);
  p192_fe_mul(r, r, t1);

  /* r = x127^(2^1) */
  p192_fe_sqr(r, r);

  /* r = r^(2^62) * x62 */
  p192_fe_sqrn(r, r, 62);
  p192_fe_mul(r, r, t4);
}

static void
p192_fe_invert(p192_fe_t r, const p192_fe_t x) {
  /* Exponent: p - 2 */
  /* Bits: 127x1 1x0 62x1 1x0 1x1 */
  p192_fe_t x1;

  /* x1 = x */
  p192_fe_set(x1, x);

  /* r = x1^((p - 3) / 4) */
  p192_fe_pow_pm3d4(r, x1);

  /* r = r^(2^1) */
  p192_fe_sqr(r, r);

  /* r = r^(2^1) * x1 */
  p192_fe_sqr(r, r);
  p192_fe_mul(r, r, x1);
}

static int
p192_fe_sqrt(p192_fe_t r, const p192_fe_t x) {
  /* Exponent: (p + 1) / 4 */
  /* Bits: 128x1 62x0 */
  p192_fe_t t0, t1, t2;

  /* x1 = x */
  p192_fe_set(t0, x);

  /* x2 = x1^(2^1) * x1 */
  p192_fe_sqr(t1, t0);
  p192_fe_mul(t1, t1, t0);

  /* x4 = x2^(2^2) * x2 */
  p192_fe_sqrn(t2, t1, 2);
  p192_fe_mul(t2, t2, t1);

  /* x8 = x4^(2^4) * x4 */
  p192_fe_sqrn(t1, t2, 4);
  p192_fe_mul(t1, t1, t2);

  /* x16 = x8^(2^8) * x8 */
  p192_fe_sqrn(t2, t1, 8);
  p192_fe_mul(t2, t2, t1);

  /* x32 = x16^(2^16) * x16 */
  p192_fe_sqrn(t1, t2, 16);
  p192_fe_mul(t1, t1, t2);

  /* x64 = x32^(2^32) * x32 */
  p192_fe_sqrn(t2, t1, 32);
  p192_fe_mul(t2, t2, t1);

  /* x128 = x64^(2^64) * x64 */
  p192_fe_sqrn(r, t2, 64);
  p192_fe_mul(r, r, t2);

  /* r = x128^(2^62) */
  p192_fe_sqrn(r, r, 62);

  /* r^2 == x1 */
  p192_fe_sqr(t1, r);

  return p192_fe_equal(t1, t0);
}

static int
p192_fe_isqrt(p192_fe_t r, const p192_fe_t u, const p192_fe_t v) {
  p192_fe_t t, x, c;
  int ret;

  /* x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p */
  p192_fe_sqr(t, u);       /* u^2 */
  p192_fe_mul(c, t, u);    /* u^3 */
  p192_fe_mul(t, t, c);    /* u^5 */
  p192_fe_sqr(x, v);       /* v^2 */
  p192_fe_mul(x, x, v);    /* v^3 */
  p192_fe_mul(x, x, t);    /* v^3 * u^5 */
  p192_fe_pow_pm3d4(x, x); /* (v^3 * u^5)^((p - 3) / 4) */
  p192_fe_mul(x, x, v);    /* (v^3 * u^5)^((p - 3) / 4) * v */
  p192_fe_mul(x, x, c);    /* (v^3 * u^5)^((p - 3) / 4) * v * u^3 */

  /* x^2 * v == u */
  p192_fe_sqr(c, x);
  p192_fe_mul(c, c, v);

  ret = p192_fe_equal(c, u);

  p192_fe_set(r, x);

  return ret;
}
