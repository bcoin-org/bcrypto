/*!
 * secp256k1.h - secp256k1 for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on bitcoin-core/secp256k1:
 *   Copyright (c) 2013 Pieter Wuille
 *   https://github.com/bitcoin-core/secp256k1
 */

#ifdef TORSION_USE_64BIT
typedef uint64_t secp256k1_fe_word_t;
#define SECP256K1_FIELD_WORDS 4
#include "secp256k1_64.h"
#else
typedef uint32_t secp256k1_fe_word_t;
#define SECP256K1_FIELD_WORDS 8
#include "secp256k1_32.h"
#endif

typedef secp256k1_fe_word_t secp256k1_fe_t[SECP256K1_FIELD_WORDS];

#define secp256k1_fe_add fiat_secp256k1_add
#define secp256k1_fe_sub fiat_secp256k1_sub
#define secp256k1_fe_neg fiat_secp256k1_opp
#define secp256k1_fe_mul fiat_secp256k1_mul
#define secp256k1_fe_sqr fiat_secp256k1_square

static void
secp256k1_fe_set(secp256k1_fe_t out, const secp256k1_fe_t in) {
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];
#if SECP256K1_FIELD_WORDS == 8
  out[4] = in[4];
  out[5] = in[5];
  out[6] = in[6];
  out[7] = in[7];
#endif
}

static int
secp256k1_fe_equal(const secp256k1_fe_t a, const secp256k1_fe_t b) {
  secp256k1_fe_word_t z = 0;
  size_t i;

  for (i = 0; i < SECP256K1_FIELD_WORDS; i++)
    z |= a[i] ^ b[i];

  return z == 0;
}

static void
secp256k1_fe_sqrn(secp256k1_fe_t out, const secp256k1_fe_t in, int rounds) {
  int i;

  secp256k1_fe_set(out, in);

  for (i = 0; i < rounds; i++)
    secp256k1_fe_sqr(out, out);
}

/* https://github.com/bitcoin-core/secp256k1/blob/master/src/field_impl.h */
static void
secp256k1_fe_invert(secp256k1_fe_t out, const secp256k1_fe_t in) {
  /* 15M + 255S */
  secp256k1_fe_t x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;

  secp256k1_fe_sqr(x2, in);
  secp256k1_fe_mul(x2, x2, in);

  secp256k1_fe_sqr(x3, x2);
  secp256k1_fe_mul(x3, x3, in);

  secp256k1_fe_set(x6, x3);
  secp256k1_fe_sqrn(x6, x6, 3);
  secp256k1_fe_mul(x6, x6, x3);

  secp256k1_fe_set(x9, x6);
  secp256k1_fe_sqrn(x9, x9, 3);
  secp256k1_fe_mul(x9, x9, x3);

  secp256k1_fe_set(x11, x9);
  secp256k1_fe_sqrn(x11, x11, 2);
  secp256k1_fe_mul(x11, x11, x2);

  secp256k1_fe_set(x22, x11);
  secp256k1_fe_sqrn(x22, x22, 11);
  secp256k1_fe_mul(x22, x22, x11);

  secp256k1_fe_set(x44, x22);
  secp256k1_fe_sqrn(x44, x44, 22);
  secp256k1_fe_mul(x44, x44, x22);

  secp256k1_fe_set(x88, x44);
  secp256k1_fe_sqrn(x88, x88, 44);
  secp256k1_fe_mul(x88, x88, x44);

  secp256k1_fe_set(x176, x88);
  secp256k1_fe_sqrn(x176, x176, 88);
  secp256k1_fe_mul(x176, x176, x88);

  secp256k1_fe_set(x220, x176);
  secp256k1_fe_sqrn(x220, x220, 44);
  secp256k1_fe_mul(x220, x220, x44);

  secp256k1_fe_set(x223, x220);
  secp256k1_fe_sqrn(x223, x223, 3);
  secp256k1_fe_mul(x223, x223, x3);

  secp256k1_fe_set(t1, x223);
  secp256k1_fe_sqrn(t1, t1, 23);
  secp256k1_fe_mul(t1, t1, x22);
  secp256k1_fe_sqrn(t1, t1, 5);
  secp256k1_fe_mul(t1, t1, in);
  secp256k1_fe_sqrn(t1, t1, 3);
  secp256k1_fe_mul(t1, t1, x2);
  secp256k1_fe_sqrn(t1, t1, 2);
  secp256k1_fe_mul(out, in, t1);
}

/* https://github.com/bitcoin-core/secp256k1/blob/master/src/field_impl.h */
static int
secp256k1_fe_sqrt(secp256k1_fe_t out, const secp256k1_fe_t in) {
  /* 13M + 254S */
  secp256k1_fe_t x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
  int ret;

  secp256k1_fe_sqr(x2, in);
  secp256k1_fe_mul(x2, x2, in);

  secp256k1_fe_sqr(x3, x2);
  secp256k1_fe_mul(x3, x3, in);

  secp256k1_fe_set(x6, x3);
  secp256k1_fe_sqrn(x6, x6, 3);
  secp256k1_fe_mul(x6, x6, x3);

  secp256k1_fe_set(x9, x6);
  secp256k1_fe_sqrn(x9, x9, 3);
  secp256k1_fe_mul(x9, x9, x3);

  secp256k1_fe_set(x11, x9);
  secp256k1_fe_sqrn(x11, x11, 2);
  secp256k1_fe_mul(x11, x11, x2);

  secp256k1_fe_set(x22, x11);
  secp256k1_fe_sqrn(x22, x22, 11);
  secp256k1_fe_mul(x22, x22, x11);

  secp256k1_fe_set(x44, x22);
  secp256k1_fe_sqrn(x44, x44, 22);
  secp256k1_fe_mul(x44, x44, x22);

  secp256k1_fe_set(x88, x44);
  secp256k1_fe_sqrn(x88, x88, 44);
  secp256k1_fe_mul(x88, x88, x44);

  secp256k1_fe_set(x176, x88);
  secp256k1_fe_sqrn(x176, x176, 88);
  secp256k1_fe_mul(x176, x176, x88);

  secp256k1_fe_set(x220, x176);
  secp256k1_fe_sqrn(x220, x220, 44);
  secp256k1_fe_mul(x220, x220, x44);

  secp256k1_fe_set(x223, x220);
  secp256k1_fe_sqrn(x223, x223, 3);
  secp256k1_fe_mul(x223, x223, x3);

  secp256k1_fe_set(t1, x223);
  secp256k1_fe_sqrn(t1, t1, 23);
  secp256k1_fe_mul(t1, t1, x22);
  secp256k1_fe_sqrn(t1, t1, 6);
  secp256k1_fe_mul(t1, t1, x2);
  secp256k1_fe_sqr(t1, t1);
  secp256k1_fe_sqr(x2, t1);

  secp256k1_fe_sqr(t1, x2);
  ret = secp256k1_fe_equal(t1, in);

  secp256k1_fe_set(out, x2);

  return ret;
}

static void
secp256k1_fe_pow_pm3d4(secp256k1_fe_t out, const secp256k1_fe_t in) {
  /* Compute a^((p - 3) / 4) with sliding window. */
  /* 41M + 253S */
  secp256k1_fe_t t2, t3, t4, t8, t16, t32, t64, t252, t255;
  int i;

  secp256k1_fe_sqr(t2, in);
  secp256k1_fe_mul(t3, t2, in);
  secp256k1_fe_sqr(t4, t2);
  secp256k1_fe_sqr(t8, t4);
  secp256k1_fe_sqr(t16, t8);
  secp256k1_fe_sqr(t32, t16);
  secp256k1_fe_sqr(t64, t32);

  secp256k1_fe_sqr(t252, t64);
  secp256k1_fe_mul(t252, t252, t64);
  secp256k1_fe_mul(t252, t252, t32);
  secp256k1_fe_mul(t252, t252, t16);
  secp256k1_fe_mul(t252, t252, t8);
  secp256k1_fe_mul(t252, t252, t4);

  secp256k1_fe_mul(t255, t252, t2);
  secp256k1_fe_mul(t255, t255, in);

  secp256k1_fe_set(out, t255);

  for (i = 0; i < 26; i++) {
    secp256k1_fe_sqrn(out, out, 8);
    secp256k1_fe_mul(out, out, t255);
  }

  secp256k1_fe_sqrn(out, out, 8);
  secp256k1_fe_mul(out, out, t252);
  secp256k1_fe_mul(out, out, t2);

  secp256k1_fe_sqrn(out, out, 8);
  secp256k1_fe_mul(out, out, t255);

  secp256k1_fe_sqrn(out, out, 8);
  secp256k1_fe_mul(out, out, t255);

  secp256k1_fe_sqrn(out, out, 8);
  secp256k1_fe_mul(out, out, t252);

  secp256k1_fe_sqrn(out, out, 6);
  secp256k1_fe_mul(out, out, t8);
  secp256k1_fe_mul(out, out, t3);
}

static int
secp256k1_fe_isqrt(secp256k1_fe_t r,
                   const secp256k1_fe_t u,
                   const secp256k1_fe_t v) {
  /* 48M + 256S */
  secp256k1_fe_t u2, u3, u5, v3, p, x, c;
  int ret;

  /* x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p */
  secp256k1_fe_sqr(u2, u);
  secp256k1_fe_mul(u3, u2, u);
  secp256k1_fe_mul(u5, u3, u2);
  secp256k1_fe_sqr(v3, v);
  secp256k1_fe_mul(v3, v3, v);
  secp256k1_fe_mul(p, u5, v3);
  secp256k1_fe_pow_pm3d4(p, p);
  secp256k1_fe_mul(x, u3, v);
  secp256k1_fe_mul(x, x, p);

  /* x^2 * v == u */
  secp256k1_fe_sqr(c, x);
  secp256k1_fe_mul(c, c, v);
  ret = secp256k1_fe_equal(c, u);

  secp256k1_fe_set(r, x);

  return ret;
}
