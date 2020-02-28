/*!
 * p251.h - p251 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifdef TORSION_USE_64BIT
typedef uint64_t p251_fe_word_t;
#define P251_FIELD_WORDS 5
#include "p251_64.h"
#else
typedef uint32_t p251_fe_word_t;
#define P251_FIELD_WORDS 10
#include "p251_32.h"
#endif

typedef p251_fe_word_t p251_fe_t[P251_FIELD_WORDS];

#define p251_fe_add fiat_p251_add
#define p251_fe_sub fiat_p251_sub
#define p251_fe_neg fiat_p251_opp
#define p251_fe_mul fiat_p251_carry_mul
#define p251_fe_sqr fiat_p251_carry_square

static void
p251_fe_set(p251_fe_t out, const p251_fe_t in) {
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];
  out[4] = in[4];
#if P251_FIELD_WORDS == 10
  out[5] = in[5];
  out[6] = in[6];
  out[7] = in[7];
  out[8] = in[8];
  out[9] = in[9];
#endif
}

static int
p251_fe_equal(const p251_fe_t a, const p251_fe_t b) {
  uint32_t z = 0;
  uint8_t u[32];
  uint8_t v[32];
  size_t i;

  fiat_p251_to_bytes(u, a);
  fiat_p251_to_bytes(v, b);

  for (i = 0; i < 32; i++)
    z |= (uint32_t)u[i] ^ (uint32_t)v[i];

  return (z - 1) >> 31;
}

static void
p251_fe_sqrn(p251_fe_t out, const p251_fe_t in, int rounds) {
  int i;

  p251_fe_set(out, in);

  for (i = 0; i < rounds; i++)
    p251_fe_sqr(out, out);
}

static void
p251_fe_invert(p251_fe_t out, const p251_fe_t in) {
  /* https://github.com/stegos/stegos/blob/532a15a/crypto/src/curve1174/fq51.rs#L454 */
  p251_fe_t w, t1, t2, x3, x5;

  p251_fe_sqr(w, in);
  p251_fe_mul(x3, w, in);
  p251_fe_mul(x5, x3, w);

  p251_fe_sqr(w, x3);
  p251_fe_sqr(t1, w);
  p251_fe_mul(w, x3, t1);

  p251_fe_sqr(t1, w);
  p251_fe_sqr(w, t1);
  p251_fe_mul(t1, x3, w);
  p251_fe_set(t2, t1);
  p251_fe_sqrn(t1, t1, 6);
  p251_fe_mul(w, t1, t2);

  p251_fe_sqr(t1, w);
  p251_fe_sqr(w, t1);
  p251_fe_mul(t1, x3, w);
  p251_fe_set(t2, t1);
  p251_fe_sqrn(t1, t1, 14);
  p251_fe_mul(w, t1, t2);

  p251_fe_sqr(t1, w);
  p251_fe_sqr(w, t1);
  p251_fe_mul(t1, x3, w);
  p251_fe_set(t2, t1);
  p251_fe_sqrn(t1, t1, 30);
  p251_fe_mul(w, t1, t2);

  p251_fe_set(t2, w);
  p251_fe_sqrn(w, w, 60);
  p251_fe_mul(t1, w, t2);

  p251_fe_sqr(w, t1);
  p251_fe_sqr(t1, w);
  p251_fe_mul(w, x3, t1);
  p251_fe_set(t2, w);
  p251_fe_sqrn(w, w, 122);
  p251_fe_mul(t1, w, t2);

  p251_fe_sqr(w, t1);
  p251_fe_mul(t1, w, in);
  p251_fe_sqr(w, t1);
  p251_fe_sqr(t1, w);
  p251_fe_mul(w, x3, t1);

  p251_fe_sqr(t1, w);
  p251_fe_sqr(w, t1);
  p251_fe_sqr(t1, w);
  p251_fe_sqr(w, t1);
  p251_fe_mul(out, w, x5);
}

static int
p251_fe_sqrt(p251_fe_t out, const p251_fe_t in) {
  /* https://github.com/stegos/stegos/blob/532a15a/crypto/src/curve1174/fq51.rs#L536 */
  p251_fe_t w, t1, t2, t8, t16, t32, t64;
  int ret;

  p251_fe_sqr(w, in);
  p251_fe_mul(t1, w, in);
  p251_fe_sqr(w, t1);
  p251_fe_sqr(t2, w);
  p251_fe_mul(w, t1, t2);

  p251_fe_set(t2, w);
  p251_fe_sqrn(w, w, 4);
  p251_fe_mul(t8, t2, w);

  p251_fe_set(w, t8);
  p251_fe_sqrn(w, w, 8);
  p251_fe_mul(t16, t8, w);

  p251_fe_set(w, t16);
  p251_fe_sqrn(w, w, 16);
  p251_fe_mul(t32, t16, w);

  p251_fe_set(w, t32);
  p251_fe_sqrn(w, w, 32);
  p251_fe_mul(t64, t32, w);

  p251_fe_set(w, t64);
  p251_fe_sqrn(w, w, 64);
  p251_fe_mul(t1, t64, w);

  p251_fe_sqrn(t1, t1, 64);
  p251_fe_mul(w, t64, t1);

  p251_fe_sqrn(w, w, 32);
  p251_fe_mul(t1, t32, w);

  p251_fe_sqrn(t1, t1, 16);
  p251_fe_mul(w, t16, t1);

  p251_fe_sqrn(w, w, 8);
  p251_fe_mul(t1, t8, w);

  p251_fe_sqr(w, t1);

  p251_fe_sqr(t1, w);
  ret = p251_fe_equal(t1, in);

  p251_fe_set(out, w);

  return ret;
}

static void
p251_fe_pow_pm3d4(p251_fe_t out, const p251_fe_t in) {
  /* Compute a^((p - 3) / 4) with sliding window. */
  p251_fe_t t1, t2, t3, t4, t8, t16, t32, t64, t254, t255;
  int i;

  p251_fe_set(t1, in);
  p251_fe_sqr(t2, t1);
  p251_fe_mul(t3, t2, t1);
  p251_fe_sqr(t4, t2);
  p251_fe_sqr(t8, t4);
  p251_fe_sqr(t16, t8);
  p251_fe_sqr(t32, t16);
  p251_fe_sqr(t64, t32);

  p251_fe_sqr(t254, t64);
  p251_fe_mul(t254, t254, t64);
  p251_fe_mul(t254, t254, t32);
  p251_fe_mul(t254, t254, t16);
  p251_fe_mul(t254, t254, t8);
  p251_fe_mul(t254, t254, t4);
  p251_fe_mul(t254, t254, t2);

  p251_fe_mul(t255, t254, t1);

  p251_fe_set(out, t255);

  for (i = 0; i < 29; i++) {
    p251_fe_sqrn(out, out, 8);
    p251_fe_mul(out, out, t255);
  }

  p251_fe_sqrn(out, out, 8);
  p251_fe_mul(out, out, t254);

  p251_fe_sqrn(out, out, 1);
  p251_fe_mul(out, out, t1);
}

static int
p251_fe_isqrt(p251_fe_t r,
              const p251_fe_t u,
              const p251_fe_t v) {
  p251_fe_t u2, u3, u5, v3, p, x, c;
  int ret;

  /* x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p */
  p251_fe_sqr(u2, u);
  p251_fe_mul(u3, u2, u);
  p251_fe_mul(u5, u3, u2);
  p251_fe_sqr(v3, v);
  p251_fe_mul(v3, v3, v);
  p251_fe_mul(p, u5, v3);
  p251_fe_pow_pm3d4(p, p);
  p251_fe_mul(x, u3, v);
  p251_fe_mul(x, x, p);

  /* x^2 * v == u */
  p251_fe_sqr(c, x);
  p251_fe_mul(c, c, v);
  ret = p251_fe_equal(c, u);

  p251_fe_set(r, x);

  return ret;
}
