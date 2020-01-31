/*!
 * p448.h - p448 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on goldilocks:
 *   Copyright (c) 2014-2017 Cryptography Research, Inc.
 *   https://git.zx2c4.com/goldilocks
 */

#ifdef TORSION_USE_64BIT
typedef uint64_t p448_fe_word_t;
#define P448_FIELD_WORDS 8
#include "p448_64.h"
#else
typedef uint32_t p448_fe_word_t;
#define P448_FIELD_WORDS 18
#include "p448_32.h"
#endif

typedef p448_fe_word_t p448_fe_t[P448_FIELD_WORDS];

#define p448_fe_add fiat_p448_add
#define p448_fe_sub fiat_p448_sub
#define p448_fe_neg fiat_p448_opp
#define p448_fe_mul fiat_p448_carry_mul
#define p448_fe_sqr fiat_p448_carry_square

static void
p448_fe_set(p448_fe_t out, const p448_fe_t in) {
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];
  out[4] = in[4];
  out[5] = in[5];
  out[6] = in[6];
  out[7] = in[7];
#if P448_FIELD_WORDS == 18
  out[8] = in[8];
  out[9] = in[9];
  out[10] = in[10];
  out[11] = in[11];
  out[12] = in[12];
  out[13] = in[13];
  out[14] = in[14];
  out[15] = in[15];
  out[16] = in[16];
  out[17] = in[17];
#endif
}

static int
p448_fe_equal(const p448_fe_t a, const p448_fe_t b) {
  uint32_t z = 0;
  uint8_t u[56];
  uint8_t v[56];
  size_t i;

  fiat_p448_to_bytes(u, a);
  fiat_p448_to_bytes(v, b);

  for (i = 0; i < 56; i++)
    z |= (uint32_t)u[i] ^ (uint32_t)v[i];

  return (z - 1) >> 31;
}

static void
p448_fe_sqrn(p448_fe_t out, const p448_fe_t in, int rounds) {
  int i;

  p448_fe_set(out, in);

  for (i = 0; i < rounds; i++)
    p448_fe_sqr(out, out);
}

static int
p448_fe_isr(p448_fe_t a, const p448_fe_t x) {
  static const p448_fe_t ONE = {1, 0};
  p448_fe_t L0, L1, L2;

  p448_fe_sqr(L1, x);
  p448_fe_mul(L2, x, L1);
  p448_fe_sqr(L1, L2);
  p448_fe_mul(L2, x, L1);
  p448_fe_sqrn(L1, L2, 3);
  p448_fe_mul(L0, L2, L1);
  p448_fe_sqrn(L1, L0, 3);
  p448_fe_mul(L0, L2, L1);
  p448_fe_sqrn(L2, L0, 9);
  p448_fe_mul(L1, L0, L2);
  p448_fe_sqr(L0, L1);
  p448_fe_mul(L2, x, L0);
  p448_fe_sqrn(L0, L2, 18);
  p448_fe_mul(L2, L1, L0);
  p448_fe_sqrn(L0, L2, 37);
  p448_fe_mul(L1, L2, L0);
  p448_fe_sqrn(L0, L1, 37);
  p448_fe_mul(L1, L2, L0);
  p448_fe_sqrn(L0, L1, 111);
  p448_fe_mul(L2, L1, L0);
  p448_fe_sqr(L0, L2);
  p448_fe_mul(L1, x, L0);
  p448_fe_sqrn(L0, L1, 223);
  p448_fe_mul(L1, L2, L0);
  p448_fe_sqr(L2, L1);
  p448_fe_mul(L0, L2, x);
  p448_fe_set(a, L1);

  return p448_fe_equal(L0, ONE);
}

static void
p448_fe_invert(p448_fe_t y, const p448_fe_t x) {
  /* sqrt(1 / x^2) == 1 / x */
  p448_fe_t t1, t2;

  p448_fe_sqr(t1, x);
  p448_fe_isr(t2, t1);

  p448_fe_sqr(t1, t2);
  p448_fe_mul(t2, t1, x);
  p448_fe_set(y, t2);
}

static int
p448_fe_sqrt(p448_fe_t a, const p448_fe_t x) {
  static const p448_fe_t ZERO = {0};
  int zero = p448_fe_equal(x, ZERO);
  int ret;
  p448_fe_t r;

  ret = p448_fe_isr(r, x);

  p448_fe_invert(a, r);

  return ret | zero;
}

static int
p448_fe_isqrt(p448_fe_t out, const p448_fe_t u, const p448_fe_t v) {
  /* sqrt(1 / (u * v)) * u == sqrt(u / v) */
  static const p448_fe_t ZERO = {0};
  int zero = p448_fe_equal(u, ZERO);
  int ret;
  p448_fe_t t, r;

  p448_fe_mul(t, u, v);

  ret = p448_fe_isr(r, t);

  p448_fe_mul(t, r, u);
  p448_fe_set(out, t);

  return ret | zero;
}

static void
p448_clamp(unsigned char *raw) {
  raw[0] &= 0xfc; /* -4 */
  raw[55] &= 0xff;
  raw[55] |= 0x80;
}
