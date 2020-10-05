/*!
 * secp256k1.h - secp256k1 for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Resources:
 *   https://briansmith.org/ecc-inversion-addition-chains-01#secp256k1_field_inversion
 */

#if defined(TORSION_USE_LIBSECP256K1)
#  if defined(TORSION_HAVE_INT128)
typedef uint64_t secp256k1_fe_word_t;
#    define SECP256K1_FIELD_WORDS 5
#    include "libsecp256k1_64.h"
#  else
typedef uint32_t secp256k1_fe_word_t;
#    define SECP256K1_FIELD_WORDS 10
#    include "libsecp256k1_32.h"
#  endif
#else /* !TORSION_USE_LIBSECP256K1 */
#  if defined(TORSION_HAVE_INT128)
typedef uint64_t secp256k1_fe_word_t;
#    define SECP256K1_FIELD_WORDS 4
#    include "secp256k1_64.h"
#  else
typedef uint32_t secp256k1_fe_word_t;
#    define SECP256K1_FIELD_WORDS 8
#    include "secp256k1_32.h"
#  endif
#endif /* !TORSION_USE_LIBSECP256K1 */

#if defined(TORSION_USE_LIBSECP256K1)
#  define fiat_secp256k1_mul fiat_secp256k1_carry_mul
#  define fiat_secp256k1_square fiat_secp256k1_carry_square
#  define fiat_secp256k1_to_montgomery NULL
#  define fiat_secp256k1_from_montgomery NULL
#else
#  define fiat_secp256k1_carry NULL
#endif

typedef secp256k1_fe_word_t secp256k1_fe_t[SECP256K1_FIELD_WORDS];

#define secp256k1_fe_add fiat_secp256k1_add
#define secp256k1_fe_sub fiat_secp256k1_sub
#define secp256k1_fe_neg fiat_secp256k1_opp
#define secp256k1_fe_mul fiat_secp256k1_mul
#define secp256k1_fe_sqr fiat_secp256k1_square
#define secp256k1_fe_nonzero fiat_secp256k1_nonzero

static void
secp256k1_fe_set(secp256k1_fe_t r, const secp256k1_fe_t x) {
#if defined(TORSION_USE_LIBSECP256K1)
  r[0] = x[0];
  r[1] = x[1];
  r[2] = x[2];
  r[3] = x[3];
  r[4] = x[4];
#if SECP256K1_FIELD_WORDS == 10
  r[5] = x[5];
  r[6] = x[6];
  r[7] = x[7];
  r[8] = x[8];
  r[9] = x[9];
#endif
#else /* !TORSION_USE_LIBSECP256K1 */
  r[0] = x[0];
  r[1] = x[1];
  r[2] = x[2];
  r[3] = x[3];
#if SECP256K1_FIELD_WORDS == 8
  r[4] = x[4];
  r[5] = x[5];
  r[6] = x[6];
  r[7] = x[7];
#endif
#endif /* !TORSION_USE_LIBSECP256K1 */
}

static int
secp256k1_fe_equal(const secp256k1_fe_t x, const secp256k1_fe_t y) {
  secp256k1_fe_word_t z = 0;

#if defined(TORSION_USE_LIBSECP256K1)
  secp256k1_fe_t c;
  secp256k1_fe_sub(c, x, y);
  secp256k1_fe_nonzero(&z, c);
#else /* !TORSION_USE_LIBSECP256K1 */
  size_t i;

  for (i = 0; i < SECP256K1_FIELD_WORDS; i++)
    z |= x[i] ^ y[i];

  z = (z >> 1) | (z & 1);
#endif /* !TORSION_USE_LIBSECP256K1 */

  return (z - 1) >> (sizeof(z) * CHAR_BIT - 1);
}

static void
secp256k1_fe_sqrn(secp256k1_fe_t r, const secp256k1_fe_t x, int rounds) {
  int i;

  secp256k1_fe_sqr(r, x);

  for (i = 1; i < rounds; i++)
    secp256k1_fe_sqr(r, r);
}

static void
secp256k1_fe_pow_core(secp256k1_fe_t r,
                      const secp256k1_fe_t x1,
                      const secp256k1_fe_t x2) {
  /* Exponent: (p - 47) / 64 */
  /* Bits: 223x1 1x0 22x1 4x0 */
  secp256k1_fe_t t1, t2, t3, t4;

  /* x3 = x2^(2^1) * x1 */
  secp256k1_fe_sqr(t1, x2);
  secp256k1_fe_mul(t1, t1, x1);

  /* x6 = x3^(2^3) * x3 */
  secp256k1_fe_sqrn(t2, t1, 3);
  secp256k1_fe_mul(t2, t2, t1);

  /* x9 = x6^(2^3) * x3 */
  secp256k1_fe_sqrn(t3, t2, 3);
  secp256k1_fe_mul(t3, t3, t1);

  /* x11 = x9^(2^2) * x2 */
  secp256k1_fe_sqrn(t2, t3, 2);
  secp256k1_fe_mul(t2, t2, x2);

  /* x22 = x11^(2^11) * x11 */
  secp256k1_fe_sqrn(t3, t2, 11);
  secp256k1_fe_mul(t3, t3, t2);

  /* x44 = x22^(2^22) * x22 */
  secp256k1_fe_sqrn(t2, t3, 22);
  secp256k1_fe_mul(t2, t2, t3);

  /* x88 = x44^(2^44) * x44 */
  secp256k1_fe_sqrn(t4, t2, 44);
  secp256k1_fe_mul(t4, t4, t2);

  /* x176 = x88^(2^88) * x88 */
  secp256k1_fe_sqrn(r, t4, 88);
  secp256k1_fe_mul(r, r, t4);

  /* x220 = x176^(2^44) * x44 */
  secp256k1_fe_sqrn(r, r, 44);
  secp256k1_fe_mul(r, r, t2);

  /* x223 = x220^(2^3) * x3 */
  secp256k1_fe_sqrn(r, r, 3);
  secp256k1_fe_mul(r, r, t1);

  /* r = x223^(2^1) */
  secp256k1_fe_sqr(r, r);

  /* r = r^(2^22) * x22 */
  secp256k1_fe_sqrn(r, r, 22);
  secp256k1_fe_mul(r, r, t3);

  /* r = r^(2^4) */
  secp256k1_fe_sqrn(r, r, 4);
}

static void
secp256k1_fe_pow_pm3d4(secp256k1_fe_t r, const secp256k1_fe_t x) {
  /* Exponent: (p - 3) / 4 */
  /* Bits: 223x1 1x0 22x1 4x0 1x1 1x0 2x1 */
  secp256k1_fe_t x1, x2;

  /* x1 = x */
  secp256k1_fe_set(x1, x);

  /* x2 = x1^(2^1) * x1 */
  secp256k1_fe_sqr(x2, x1);
  secp256k1_fe_mul(x2, x2, x1);

  /* r = x1^((p - 47) / 64) */
  secp256k1_fe_pow_core(r, x1, x2);

  /* r = r^(2^1) * x1 */
  secp256k1_fe_sqr(r, r);
  secp256k1_fe_mul(r, r, x1);

  /* r = r^(2^1) */
  secp256k1_fe_sqr(r, r);

  /* r = r^(2^2) * x2 */
  secp256k1_fe_sqrn(r, r, 2);
  secp256k1_fe_mul(r, r, x2);
}

static void
secp256k1_fe_invert(secp256k1_fe_t r, const secp256k1_fe_t x) {
  /* Exponent: p - 2 */
  /* Bits: 223x1 1x0 22x1 4x0 1x1 1x0 2x1 1x0 1x1 */
  secp256k1_fe_t x1, x2;

  /* x1 = x */
  secp256k1_fe_set(x1, x);

  /* x2 = x1^(2^1) * x1 */
  secp256k1_fe_sqr(x2, x1);
  secp256k1_fe_mul(x2, x2, x1);

  /* r = x1^((p - 47) / 64) */
  secp256k1_fe_pow_core(r, x1, x2);

  /* r = r^(2^1) * x1 */
  secp256k1_fe_sqr(r, r);
  secp256k1_fe_mul(r, r, x1);

  /* r = r^(2^1) */
  secp256k1_fe_sqr(r, r);

  /* r = r^(2^2) * x2 */
  secp256k1_fe_sqrn(r, r, 2);
  secp256k1_fe_mul(r, r, x2);

  /* r = r^(2^1) */
  secp256k1_fe_sqr(r, r);

  /* r = r^(2^1) * x1 */
  secp256k1_fe_sqr(r, r);
  secp256k1_fe_mul(r, r, x1);
}

static int
secp256k1_fe_sqrt(secp256k1_fe_t r, const secp256k1_fe_t x) {
  /* Exponent: (p + 1) / 4 */
  /* Bits: 223x1 1x0 22x1 4x0 2x1 2x0 */
  secp256k1_fe_t x1, x2;

  /* x1 = x */
  secp256k1_fe_set(x1, x);

  /* x2 = x1^(2^1) * x1 */
  secp256k1_fe_sqr(x2, x1);
  secp256k1_fe_mul(x2, x2, x1);

  /* r = x1^((p - 47) / 64) */
  secp256k1_fe_pow_core(r, x1, x2);

  /* r = r^(2^2) * x2 */
  secp256k1_fe_sqrn(r, r, 2);
  secp256k1_fe_mul(r, r, x2);

  /* r = r^(2^2) */
  secp256k1_fe_sqrn(r, r, 2);

  /* r^2 == x1 */
  secp256k1_fe_sqr(x2, r);

  return secp256k1_fe_equal(x2, x1);
}

static int
secp256k1_fe_isqrt(secp256k1_fe_t r,
                   const secp256k1_fe_t u,
                   const secp256k1_fe_t v) {
  secp256k1_fe_t t, x, c;
  int ret;

  /* x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p */
  secp256k1_fe_sqr(t, u);       /* u^2 */
  secp256k1_fe_mul(c, t, u);    /* u^3 */
  secp256k1_fe_mul(t, t, c);    /* u^5 */
  secp256k1_fe_sqr(x, v);       /* v^2 */
  secp256k1_fe_mul(x, x, v);    /* v^3 */
  secp256k1_fe_mul(x, x, t);    /* v^3 * u^5 */
  secp256k1_fe_pow_pm3d4(x, x); /* (v^3 * u^5)^((p - 3) / 4) */
  secp256k1_fe_mul(x, x, v);    /* (v^3 * u^5)^((p - 3) / 4) * v */
  secp256k1_fe_mul(x, x, c);    /* (v^3 * u^5)^((p - 3) / 4) * v * u^3 */

  /* x^2 * v == u */
  secp256k1_fe_sqr(c, x);
  secp256k1_fe_mul(c, c, v);

  ret = secp256k1_fe_equal(c, u);

  secp256k1_fe_set(r, x);

  return ret;
}
