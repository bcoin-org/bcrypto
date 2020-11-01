/*!
 * mpi.c - multi-precision integers for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * A from-scratch reimplementation of GMP.
 *
 * References:
 *
 *   [KNUTH] The Art of Computer Programming,
 *           Volume 2, Seminumerical Algorithms
 *     Donald E. Knuth
 *     https://www-cs-faculty.stanford.edu/~knuth/taocp.html
 *
 *   [MONT] Efficient Software Implementations of Modular Exponentiation
 *     Shay Gueron
 *     https://eprint.iacr.org/2011/239.pdf
 *
 *   [DIV] Improved division by invariant integers
 *     Niels Möller, Torbjörn Granlund
 *     https://gmplib.org/~tege/division-paper.pdf
 *
 *   [JACOBI] A Binary Algorithm for the Jacobi Symbol
 *     J. Shallit, J. Sorenson
 *     https://www.researchgate.net/publication/2273750
 *
 *   [HANDBOOK] Handbook of Applied Cryptography
 *     A. Menezes, P. van Oorschot, S. Vanstone
 *
 *   [LUCAS] Lucas Pseudoprimes
 *     R. Baillie, S. Wagstaff
 *     https://www.ams.org/journals/mcom/1980-35-152/S0025-5718-1980-0583518-6/S0025-5718-1980-0583518-6.pdf
 *
 *   [BPSW] The Baillie-PSW Primality Test
 *     Thomas R. Nicely
 *     https://web.archive.org/web/20130828131627/http://www.trnicely.net/misc/bpsw.html
 */

#include <stdint.h>
#include <stdlib.h>

#include "internal.h"
#include "mpi.h"

/*
 * Macros
 */

#define MP_MIN(x, y) ((x) < (y) ? (x) : (y))
#define MP_MAX(x, y) ((x) > (y) ? (x) : (y))
#define MP_ABS(x) ((x) < 0 ? -(x) : (x))

/* Max stack allocation size for alloca: */
/* 1536 bytes (three 4096 bit RSA moduli). */
#define MP_AM ((3 * 4096) / MP_LIMB_BITS + 1)

#if defined(__GNUC__) || __has_builtin(__builtin_alloca)
#  define mp_alloca __builtin_alloca
#elif defined(_MSC_VER)
#  include <malloc.h>
#  define mp_alloca _alloca
#endif

#if defined(mp_alloca)
#  define mp_alloca_limbs(n) ((mp_limb_t *)mp_alloca((n) * sizeof(mp_limb_t)))
#  define mp_alloc_vla(n) ((n) > MP_AM ? mp_alloc_limbs(n) : mp_alloca_limbs(n))
#  define mp_free_vla(p, n) do { if ((n) > MP_AM) mp_free_limbs(p); } while (0)
#else
#  define mp_alloc_vla(n) mp_alloc_limbs(n)
#  define mp_free_vla(p, n) mp_free_limbs(p)
#endif

#if defined(TORSION_HAVE_ASM_X64) && MP_LIMB_BITS == 64
/* For some reason clang sucks at inlining ASM, but
   is extremely good at generating 128 bit carry code.
   GCC is the exact opposite! */
#  define MP_HAVE_ASM
#  ifndef __clang__
#    define MP_USE_ASM
#  endif
#endif

#if defined(MP_USE_ASM)
/* [z, c] = x + y */
#define mp_add(z, c, x, y) \
  __asm__ (                \
    "addq %q1, %q0\n"      \
    "movq $0, %q1\n"       \
    "setc %b1\n"           \
    : "=r" (z), "=r" (c)   \
    : "0" (x), "1" (y)     \
    : "cc"                 \
  )

/* [z, c] = x - y */
#define mp_sub(z, c, x, y) \
  __asm__ (                \
    "subq %q1, %q0\n"      \
    "movq $0, %q1\n"       \
    "sbbq %q1, %q1\n"      \
    "negq %q1\n"           \
    : "=r" (z), "=r" (c)   \
    : "0" (x), "1" (y)     \
    : "cc"                 \
  )

/* [hi, lo] = x * y */
#define mp_mul(hi, lo, x, y) \
  __asm__ (                  \
    "mulq %q3\n"             \
    : "=a" (lo), "=d" (hi)   \
    : "%0" (x), "rm" (y)     \
  )

/* [hi, lo] = x^2 */
#define mp_sqr(hi, lo, x)  \
  __asm__ (                \
    "mulq %%rax\n"         \
    : "=a" (lo), "=d" (hi) \
    : "0" (x)              \
  )

/* [z, c] = x + y + c */
#define mp_add_1(z, c, x, y) \
  __asm__ (                  \
    "addq %q1, %q0\n"        \
    "movq $0, %q1\n"         \
    "setc %b1\n"             \
    "addq %q4, %q0\n"        \
    "adcq $0, %q1\n"         \
    : "=r" (z), "=r" (c)     \
    : "0" (x), "1" (y),      \
      "rm" (c)               \
    : "cc"                   \
  )

/* [z, c] = x - y - c */
#define mp_sub_1(z, c, x, y) \
  __asm__ (                  \
    "subq %q1, %q0\n"        \
    "movq $0, %q1\n"         \
    "sbbq %q1, %q1\n"        \
    "subq %q4, %q0\n"        \
    "sbbq $0, %q1\n"         \
    "negq %q1\n"             \
    : "=r" (z), "=r" (c)     \
    : "0" (x), "1" (y),      \
      "rm" (c)               \
    : "cc"                   \
  )

/* [z, c] = x * y + c */
#define mp_mul_1(z, c, x, y)  \
  __asm__ (                   \
    "mulq %q3\n"              \
    "addq %q4, %%rax\n"       \
    "adcq $0, %%rdx\n"        \
    : "=a" (z), "=&d" (c)     \
    : "%0" (x), "rm" (y),     \
      "rm" (c)                \
    : "cc"                    \
  )

/* [z, c] = x * y + z + c */
#define mp_addmul_1(z, c, x, y) \
  __asm__ (                     \
    "mulq %q3\n"                \
    "addq %q5, %%rax\n"         \
    "adcq $0, %%rdx\n"          \
    "addq %q4, %%rax\n"         \
    "adcq $0, %%rdx\n"          \
    : "=a" (z), "=&d" (c)       \
    : "%0" (x), "rm" (y),       \
      "rm" (z), "rm" (c)        \
    : "cc"                      \
  )

/* [z, c] = z - x * y - c */
#define mp_submul_1(z, c, x, y) \
  __asm__ (                     \
    "movq %q2, %%rax\n"         \
    "mulq %q3\n"                \
    "xorl %k1, %k1\n"           \
    "subq %%rax, %q0\n"         \
    "sbbq %%rdx, %q1\n"         \
    "subq %q4, %q0\n"           \
    "sbbq $0, %q1\n"            \
    "negq %q1\n"                \
    : "+r" (z), "=&r" (c)       \
    : "%rm" (x), "rm" (y),      \
      "rm" (c)                  \
    : "cc", "rax", "rdx"        \
  )
#else /* !MPI_USE_ASM */
#define mp_add(z, c, x, y) do {        \
  mp_wide_t _w = (mp_wide_t)(x) + (y); \
  (c) = _w >> MP_LIMB_BITS;            \
  (z) = _w;                            \
} while (0)

#define mp_sub(z, c, x, y) do {        \
  mp_wide_t _w = (mp_wide_t)(x) - (y); \
  (c) = -(_w >> MP_LIMB_BITS);         \
  (z) = _w;                            \
} while (0)

#define mp_mul(hi, lo, x, y) do {      \
  mp_wide_t _w = (mp_wide_t)(x) * (y); \
  (hi) = _w >> MP_LIMB_BITS;           \
  (lo) = _w;                           \
} while (0)

#define mp_sqr(hi, lo, x) do {         \
  mp_wide_t _w = (mp_wide_t)(x) * (x); \
  (hi) = _w >> MP_LIMB_BITS;           \
  (lo) = _w;                           \
} while (0)

#define mp_add_1(z, c, x, y) do {            \
  mp_wide_t _w = (mp_wide_t)(x) + (y) + (c); \
  (c) = _w >> MP_LIMB_BITS;                  \
  (z) = _w;                                  \
} while (0)

#define mp_sub_1(z, c, x, y) do {            \
  mp_wide_t _w = (mp_wide_t)(x) - (y) - (c); \
  (c) = -(_w >> MP_LIMB_BITS);               \
  (z) = _w;                                  \
} while (0)

#define mp_mul_1(z, c, x, y) do {            \
  mp_wide_t _w = (mp_wide_t)(x) * (y) + (c); \
  (c) = _w >> MP_LIMB_BITS;                  \
  (z) = _w;                                  \
} while (0)

#define mp_addmul_1(z, c, x, y) do {               \
  mp_wide_t _w = (mp_wide_t)(x) * (y) + (z) + (c); \
  (c) = _w >> MP_LIMB_BITS;                        \
  (z) = _w;                                        \
} while (0)

#define mp_submul_1(z, c, x, y) do {                          \
  mp_wide_t _w = (mp_wide_t)(z) - (mp_wide_t)(x) * (y) - (c); \
  (c) = -(_w >> MP_LIMB_BITS);                                \
  (z) = _w;                                                   \
} while (0)
#endif /* !MPI_USE_ASM */

/*
 * Types
 */

typedef struct mp_divisor_s {
  mp_limb_t *up;
  mp_limb_t *vp;
  mp_limb_t inv;
  int shift;
  int size;
} mp_divisor_t;

/*
 * MPV Declarations
 */

static TORSION_INLINE int
mpv_set_1(mp_limb_t *xp, mp_limb_t y);

static TORSION_INLINE int
mpv_set(mp_limb_t *zp, const mp_limb_t *xp, int xn);

static TORSION_INLINE int
mpv_cmp_1(const mp_limb_t *xp, int xn, mp_limb_t y);

static TORSION_INLINE int
mpv_cmp(const mp_limb_t *xp, int xn,
        const mp_limb_t *yp, int yn);

static TORSION_INLINE int
mpv_add_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y);

static TORSION_INLINE int
mpv_add(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                       const mp_limb_t *yp, int yn);

static TORSION_INLINE int
mpv_sub_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y);

static TORSION_INLINE int
mpv_sub(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                       const mp_limb_t *yp, int yn);

static TORSION_INLINE int
mpv_sub_mod(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                           const mp_limb_t *yp, int yn,
                           const mp_limb_t *mp, int mn);

static TORSION_INLINE int
mpv_mul_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y);

static TORSION_INLINE int
mpv_mul(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                       const mp_limb_t *yp, int yn);

static TORSION_INLINE int
mpv_sqr(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t *scratch);

static TORSION_INLINE int
mpv_lshift(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits);

static TORSION_INLINE int
mpv_rshift(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits);

/*
 * Allocation
 */

mp_limb_t *
mp_alloc_limbs(int size) {
  mp_limb_t *ptr;

  CHECK(size > 0);

  ptr = malloc(size * sizeof(mp_limb_t));

  if (ptr == NULL)
    torsion_abort(); /* LCOV_EXCL_LINE */

  return ptr;
}

mp_limb_t *
mp_realloc_limbs(mp_limb_t *ptr, int size) {
  CHECK(size > 0);

  ptr = realloc(ptr, size * sizeof(mp_limb_t));

  if (ptr == NULL)
    torsion_abort(); /* LCOV_EXCL_LINE */

  return ptr;
}

void
mp_free_limbs(mp_limb_t *ptr) {
  free(ptr);
}

/*
 * Limb Helpers
 */

static TORSION_INLINE int
mp_clz(mp_limb_t w) {
#if defined(MP_HAVE_ASM)
  mp_limb_t b;

  if (w == 0)
    return MP_LIMB_BITS;

  __asm__ (
    "bsrq %q1, %q0\n"
    : "=r" (b)
    : "rm" (w)
    : "cc"
  );

  return 63 - b;
#else
  mp_limb_t m = MP_LIMB_C(1) << (MP_LIMB_BITS - 1);
  int b = 0;

  if (w == 0)
    return MP_LIMB_BITS;

  while ((w & m) == 0) {
    b += 1;
    m >>= 1;
  }

  return b;
#endif
}

static TORSION_INLINE int
mp_ctz(mp_limb_t w) {
#if defined(MP_HAVE_ASM)
  mp_limb_t b;

  if (w == 0)
    return MP_LIMB_BITS;

  __asm__ (
    "bsfq %q1, %q0\n"
    : "=r" (b)
    : "rm" (w)
    : "cc"
  );

  return b;
#else
  int b = 0;

  if (w == 0)
    return MP_LIMB_BITS;

  while ((w & 1) == 0) {
    b += 1;
    w >>= 1;
  }

  return b;
#endif
}

static TORSION_INLINE int
mp_bitlen(mp_limb_t w) {
#if defined(MP_HAVE_ASM)
  mp_limb_t b;

  if (w == 0)
    return 0;

  __asm__ (
    "bsrq %q1, %q0\n"
    : "=r" (b)
    : "rm" (w)
    : "cc"
  );

  return b + 1;
#else
  int b = 0;

  while (w != 0) {
    b += 1;
    w >>= 1;
  }

  return b;
#endif
}

static TORSION_INLINE int
mp_gt_2(mp_limb_t x1, mp_limb_t x0, mp_limb_t y1, mp_limb_t y0) {
  return x1 > y1 || (x1 == y1 && x0 > y0);
}

static TORSION_INLINE int
mp_cast_size(size_t n) {
  CHECK(n <= (size_t)MP_SIZE_MAX);
  return n;
}

/*
 * MPN Interface
 */

/*
 * Initialization
 */

void
mpn_zero(mp_limb_t *xp, int xn) {
  int i;

  for (i = 0; i < xn; i++)
    xp[i] = 0;
}

/*
 * Uninitialization
 */

void
torsion_cleanse(void *, size_t);

void
mpn_cleanse(mp_limb_t *xp, int xn) {
  torsion_cleanse(xp, xn * sizeof(mp_limb_t));
}

/*
 * Assignment
 */

void
mpn_set_1(mp_limb_t *xp, int xn, mp_limb_t y) {
  ASSERT(xn > 0);

  xp[0] = y;

  mpn_zero(xp + 1, xn - 1);
}

void
mpn_copy(mp_limb_t *zp, const mp_limb_t *xp, int xn) {
  int i;

  for (i = 0; i < xn; i++)
    zp[i] = xp[i];
}

/*
 * Comparison
 */

int
mpn_zero_p(const mp_limb_t *xp, int xn) {
  int i;

  for (i = 0; i < xn; i++) {
    if (xp[i] != 0)
      return 0;
  }

  return 1;
}

int
mpn_cmp(const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  int i;

  for (i = n - 1; i >= 0; i--) {
    if (xp[i] != yp[i])
      return xp[i] < yp[i] ? -1 : 1;
  }

  return 0;
}

/*
 * Addition
 */

mp_limb_t
mpn_add_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y) {
  mp_limb_t c = y;
  int i;

  for (i = 0; i < xn; i++) {
    /* [z, c] = x + c */
    mp_add(zp[i], c, xp[i], c);
  }

  return c;
}

mp_limb_t
mpn_add_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  mp_limb_t c = 0;
  int i;

  for (i = 0; i < n; i++) {
    /* [z, c] = x + y + c */
    mp_add_1(zp[i], c, xp[i], yp[i]);
  }

  return c;
}

mp_limb_t
mpn_add(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                       const mp_limb_t *yp, int yn) {
  mp_limb_t c;

  CHECK(xn >= yn);

  c = mpn_add_n(zp, xp, yp, yn);

  if (xn > yn)
    c = mpn_add_1(zp + yn, xp + yn, xn - yn, c);

  return c;
}

/*
 * Subtraction
 */

mp_limb_t
mpn_sub_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y) {
  mp_limb_t c = y;
  int i;

  for (i = 0; i < xn; i++) {
    /* [z, c] = x - c */
    mp_sub(zp[i], c, xp[i], c);
  }

  return c;
}

mp_limb_t
mpn_sub_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  mp_limb_t c = 0;
  int i;

  for (i = 0; i < n; i++) {
    /* [z, c] = x - y - c */
    mp_sub_1(zp[i], c, xp[i], yp[i]);
  }

  return c;
}

mp_limb_t
mpn_sub(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                       const mp_limb_t *yp, int yn) {
  mp_limb_t c;

  CHECK(xn >= yn);

  c = mpn_sub_n(zp, xp, yp, yn);

  if (xn > yn)
    c = mpn_sub_1(zp + yn, xp + yn, xn - yn, c);

  return c;
}

/*
 * Multiplication
 */

mp_limb_t
mpn_mul_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y) {
  mp_limb_t c = 0;
  int i;

  for (i = 0; i < xn; i++) {
    /* [z, c] = x * y + c */
    mp_mul_1(zp[i], c, xp[i], y);
  }

  return c;
}

mp_limb_t
mpn_addmul_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y) {
  mp_limb_t c = 0;
  int i;

  for (i = 0; i < xn; i++) {
    /* [z, c] = x * y + z + c */
    mp_addmul_1(zp[i], c, xp[i], y);
  }

  return c;
}

mp_limb_t
mpn_submul_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y) {
  mp_limb_t c = 0;
  int i;

  for (i = 0; i < xn; i++) {
    /* [z, c] = z - x * y - c */
    mp_submul_1(zp[i], c, xp[i], y);
  }

  return c;
}

void
mpn_mul_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  mpn_mul(zp, xp, n, yp, n);
}

void
mpn_mul(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                       const mp_limb_t *yp, int yn) {
  int i;

  if (yn == 0) {
    mpn_zero(zp, xn);
    return;
  }

  zp[xn] = mpn_mul_1(zp, xp, xn, yp[0]);

  for (i = 1; i < yn; i++)
    zp[xn + i] = mpn_addmul_1(zp + i, xp, xn, yp[i]);
}

void
mpn_sqr(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t *scratch) {
  /* `2 * xn` limbs are required for scratch. */
  mp_limb_t *tp = scratch;
  mp_limb_t c = 0;
  mp_limb_t w;
  int i;

  if (xn == 0)
    return;

  mp_sqr(zp[1], zp[0], xp[0]);

  if (xn == 1)
    return;

  tp[0] = 0;

  mp_sqr(zp[3], zp[2], xp[1]);
  mp_mul(tp[2], tp[1], xp[0], xp[1]);

  for (i = 2; i < xn; i++) {
    mp_sqr(zp[2 * i + 1], zp[2 * i + 0], xp[i]);

    tp[2 * i - 1] = 0;
    tp[2 * i - 0] = mpn_addmul_1(tp + i, xp, i, xp[i]);
  }

  tp[2 * xn - 1] = 0;

  for (i = 1; i < 2 * xn; i++) {
    w = (tp[i] << 1) | (tp[i - 1] >> (MP_LIMB_BITS - 1));

    mp_add_1(zp[i], c, zp[i], w);
  }

  ASSERT(c == 0);
}

/*
 * Multiply + Shift
 */

mp_limb_t
mpn_mulshift(mp_limb_t *zp,
             const mp_limb_t *xp,
             const mp_limb_t *yp,
             int n, int bits,
             mp_limb_t *scratch) {
  /* Computes `z = round((x * y) / 2^bits)`.
   *
   * Constant time assuming `bits` is constant.
   *
   * `2 * n` limbs are required for scratch.
   */
  int sn = bits / MP_LIMB_BITS;
  int lo = bits % MP_LIMB_BITS;
  mp_limb_t *tp = scratch;
  int tn = n * 2;
  int zn = tn - sn;
  mp_limb_t b;

  /* Ensure L <= bits <= 2 * L. */
  ASSERT(sn >= n && sn <= n * 2);

  /* t = x * y */
  mpn_mul_n(tp, xp, yp, n);

  /* z = t >> bits */
  mpn_copy(zp, tp + sn, tn - sn);
  mpn_zero(zp + zn, n - zn);

  if (lo != 0)
    mpn_rshift(zp, zp, zn, lo);

  /* z += (t >> (bits - 1)) & 1 */
  b = mpn_get_bit(tp, tn, bits - 1);

  return mpn_add_1(zp, zp, n, b);
}

/*
 * Weak Reduction
 */

int
mpn_reduce_weak(mp_limb_t *zp,
                const mp_limb_t *xp,
                const mp_limb_t *np,
                int n, mp_limb_t hi,
                mp_limb_t *scratch) {
  /* `n` limbs are required for scratch. */
  mp_limb_t *tp = scratch;
  mp_limb_t c = mpn_sub_n(tp, xp, np, n);

  mp_sub(hi, c, hi, c);

  mpn_select(zp, xp, tp, n, c == 0);

#ifdef TORSION_VERIFY
  ASSERT(mpn_cmp(zp, np, n) < 0);
#endif

  return c == 0;
}

/*
 * Barrett Reduction
 */

void
mpn_barrett(mp_limb_t *mp, const mp_limb_t *np,
            int n, int shift, mp_limb_t *scratch) {
  /* Barrett precomputation.
   *
   * [HANDBOOK] Page 603, Section 14.3.3.
   *
   * `shift` limbs are required for scratch.
   *
   * Must have `shift + 1 - n + 1` limbs at mp.
   *
   * Result will be `shift - n + 1` limbs.
   */
  mp_limb_t *xp = scratch;
  int xn = shift + 1;

  CHECK(n > 0);
  CHECK(shift >= n * 2);

  /* m = 2^(shift * L) / n */
  mpn_zero(xp, shift);

  xp[shift] = 1;

  mpn_div(mp, xp, xn, np, n);

  CHECK(mpn_strip(mp, xn - n + 1) == shift - n + 1);
}

void
mpn_reduce(mp_limb_t *zp, const mp_limb_t *xp,
                          const mp_limb_t *mp,
                          const mp_limb_t *np,
                          int n, int shift,
                          mp_limb_t *scratch) {
  /* Barrett reduction.
   *
   * [HANDBOOK] Algorithm 14.42, Page 604, Section 14.3.3.
   *
   * `1 + shift + mn` limbs are required for scratch.
   *
   * In other words: `2 * (shift + 1) - n` limbs.
   */
  int mn = shift - n + 1;
  mp_limb_t *qp = scratch;
  mp_limb_t *hp = scratch + 1;

  /* h = x * m */
  mpn_mul(hp, xp, shift, mp, mn);

  /* h = h >> (shift * L) */
  hp += shift;

  /* q = x - h * n */
  mpn_mul(qp, hp, mn, np, n);
  mpn_sub_n(qp, xp, qp, shift);

  /* q = q - n if q >= n */
  mpn_reduce_weak(zp, qp, np, n, qp[n], hp);
}

/*
 * Montgomery Multiplication (logic from golang)
 */

void
mpn_mont(mp_limb_t *kp, mp_limb_t *rp,
         const mp_limb_t *mp, int n,
         mp_limb_t *scratch) {
  /* Montgomery precomputation.
   *
   * [HANDBOOK] Page 600, Section 14.3.2.
   *
   * `2 * n + 1` limbs are required for scratch.
   */
  mp_limb_t *xp = scratch;
  int xn = n * 2 + 1;
  mp_limb_t k, t;
  int i;

  CHECK(n > 0);

  /* k = -m^-1 mod 2^L */
  k = 2 - mp[0];
  t = mp[0] - 1;

  for (i = 1; i < MP_LIMB_BITS; i <<= 1) {
    t *= t;
    k *= (t + 1);
  }

  kp[0] = -k;

  /* r = 2^(2 * n * L) mod m */
  mpn_zero(xp, n * 2);

  xp[n * 2] = 1;

  mpn_mod(rp, xp, xn, mp, n);
}

static TORSION_INLINE mp_limb_t
mpn_montmul_inner(const mp_limb_t *xp,
                  const mp_limb_t *yp,
                  const mp_limb_t *mp,
                  int n, mp_limb_t k,
                  mp_limb_t *scratch) {
  /* Montgomery multiplication.
   *
   * [MONT] Algorithm 4 & 5, Page 5, Section 3.
   *
   * `2 * n` limbs are required for scratch.
   */
  mp_limb_t *tp = scratch;
  mp_limb_t c1, c2, c3, cx, cy;
  int i;

  ASSERT(n > 0);

  c2 = mpn_mul_1(tp, xp, n, yp[0]);
  c3 = mpn_addmul_1(tp, mp, n, tp[0] * k);

  mp_add(tp[n], c1, c2, c3);

  for (i = 1; i < n; i++) {
    c2 = mpn_addmul_1(tp + i, xp, n, yp[i]);
    c3 = mpn_addmul_1(tp + i, mp, n, tp[i] * k);

    mp_add(cx, c2, c1, c2);
    mp_add(cy, c3, cx, c3);

    c1 = c2 | c3;

    tp[n + i] = cy;
  }

  return c1;
}

void
mpn_montmul(mp_limb_t *zp,
            const mp_limb_t *xp,
            const mp_limb_t *yp,
            const mp_limb_t *mp,
            int n, mp_limb_t k,
            mp_limb_t *scratch) {
  /* Word-by-Word Montgomery Multiplication.
   *
   * [MONT] Algorithm 4, Page 5, Section 3.
   */
  mp_limb_t *tp = scratch;
  mp_limb_t c = mpn_montmul_inner(xp, yp, mp, n, k, tp);

  mpn_reduce_weak(zp, tp + n, mp, n, c, tp);
}

void
mpn_montmul_var(mp_limb_t *zp,
                const mp_limb_t *xp,
                const mp_limb_t *yp,
                const mp_limb_t *mp,
                int n, mp_limb_t k,
                mp_limb_t *scratch) {
  /* Word-by-Word Almost Montgomery Multiplication.
   *
   * [MONT] Algorithm 4, Page 5, Section 3.
   */
  mp_limb_t *tp = scratch;
  mp_limb_t c = mpn_montmul_inner(xp, yp, mp, n, k, tp);

  if (c != 0)
    mpn_sub_n(zp, tp + n, mp, n);
  else
    mpn_copy(zp, tp + n, n);
}

/*
 * Division Helpers
 */

static void
mp_div(mp_limb_t *q, mp_limb_t *r,
       mp_limb_t n1, mp_limb_t n0, mp_limb_t d) {
#if defined(MP_HAVE_ASM)
  mp_limb_t q0, r0;

  /* [q, r] = (n1 * B + n0) / d */
  __asm__ (
    "divq %q4\n"
    : "=a" (q0), "=d" (r0)
    : "0" (n0), "1" (n1), "rm" (d)
  );

  if (q != NULL)
    *q = q0;

  if (r != NULL)
    *r = r0;
#elif MP_LIMB_BITS == 64
  /* [DIV] Algorithm 1, Page 2, Section A.
   *
   * This code is basically an unrolled version
   * of the `divlu` code from Hacker's Delight.
   *
   * Having this here allows us to avoid using
   * __int128 division on non-x64 platforms.
   *
   * Logic borrowed from golang's arith.go.
   */
  static const mp_limb_t b = MP_LIMB_C(1) << MP_LOW_BITS;
  mp_limb_t q0, q1, un0, un1, vn0, vn1, rhat;
  int s;

  if (d == 0 || n1 >= d)
    torsion_abort(); /* LCOV_EXCL_LINE */

  s = mp_clz(d);

  if (s != 0) {
    n1 = (n1 << s) | (n0 >> (MP_LIMB_BITS - s));
    n0 = n0 << s;
    d <<= s;
  }

  vn1 = d >> MP_LOW_BITS;
  vn0 = d & MP_LOW_MASK;

  un1 = n0 >> MP_LOW_BITS;
  un0 = n0 & MP_LOW_MASK;

  q1 = n1 / vn1;
  rhat = n1 - q1 * vn1;

  while (q1 >= b || q1 * vn0 > rhat * b + un1) {
    q1 -= 1;
    rhat += vn1;

    if (rhat >= b)
      break;
  }

  un1 = n1 * b + un1 - q1 * d;
  q0 = un1 / vn1;
  rhat = un1 - q0 * vn1;

  while (q0 >= b || q0 * vn0 > rhat * b + un0) {
    q0 -= 1;
    rhat += vn1;

    if (rhat >= b)
      break;
  }

  if (q != NULL)
    *q = q1 * b + q0;

  if (r != NULL)
    *r = (un1 * b + un0 - q0 * d) >> s;
#else
  mp_wide_t n = ((mp_wide_t)n1 << MP_LIMB_BITS) | n0;
  mp_limb_t q0 = n / d;

  if (q != NULL)
    *q = q0;

  if (r != NULL)
    *r = n - (mp_wide_t)q0 * d;
#endif
}

static mp_limb_t
mp_inv_2by1(mp_limb_t d) {
  /* [DIV] Page 2, Section II.
   *
   * The approximate reciprocal is defined as:
   *
   *   v = ((B^2 - 1) / d) - B
   *
   * Unfortunately, the numerator here is too
   * large for hardware instructions.
   *
   * Instead, we can compute:
   *
   *   v = (B^2 - 1 - d * B) / d
   *
   * Which happens to be equivalent and allows
   * us to do a normalized division using
   * hardware instructions.
   *
   * A more programmatic way of expressing
   * this would be (where L = log2(B)):
   *
   *   v = ~(d << L) / d
   *
   * Or, in x86-64 assembly:
   *
   *   mov $0, %rax
   *   mov %[d], %rdx
   *   not %rax
   *   not %rdx
   *   div %[d]
   *   mov %rax, %[v]
   *
   * This trick was utilized by the golang
   * developers when switching away from a
   * more specialized inverse function. See
   * the discussion here[1][2].
   *
   * [1] https://go-review.googlesource.com/c/go/+/250417
   * [2] https://go-review.googlesource.com/c/go/+/250417/comment/380e8f18_ad97735c/
   */
  mp_limb_t u = d << mp_clz(d);
  mp_limb_t q;

  mp_div(&q, NULL, ~u, MP_LIMB_MAX, u);

  return q;
}

static TORSION_INLINE void
mp_div_2by1(mp_limb_t *q, mp_limb_t *r,
            mp_limb_t u1, mp_limb_t u0,
            mp_limb_t d, mp_limb_t v) {
  /* [DIV] Algorithm 4, Page 4, Section A.
   *
   * The 2-by-1 division is defined by
   * Möller & Granlund as:
   *
   *   (q1, q0) <- v * u1
   *   (q1, q0) <- (q1, q0) + (u1, u0)
   *
   *   q1 <- (q1 + 1) mod B
   *
   *   r <- (u0 - q1 * d) mod B
   *
   *   if r > q0 (unpredictable)
   *     q1 <- (q1 - 1) mod B
   *     r <- (r + d) mod B
   *
   *   if r >= d (unlikely)
   *     q1 <- q1 + 1
   *     r <- r - d
   *
   *   return q1, r
   *
   * Note that this function expects the
   * divisor to be normalized and does not
   * de-normalize the remainder.
   */
  mp_limb_t q0, q1, r0, c;

  mp_mul(q1, q0, v, u1);
  mp_add(q0, c, q0, u0);
  mp_add_1(q1, c, q1, u1);

  /* At this point, we have computed:
   *
   *   q = (((B^2 - 1) / d) - B) * (u / B) + u
   *     = ((B^2 - 1) * u) / (B * d)
   *
   * On an 8-bit machine, this implies:
   *
   *   q = (u * 0xffff) / (d << 8)
   *
   * For example, if we want to compute:
   *
   *   [q, r] = 0x421 / 0x83 = [0x08, 0x09]
   *
   * We first compute:
   *
   *   q = 0x420fbdf / 0x8300 = 0x0811
   *
   * Note that the actual quotient is
   * in the high bits of the result.
   *
   * Our remainder is trickier. We now
   * compute:
   *
   *   r = u0 - (q1 + 1) * d
   *     = 0x21 - 0x09 * 0x83
   *     = -0x047a (allowed to underflow)
   *     = 0x86 mod B
   *
   * Since 0x86 > 0x11, the first branch
   * is triggered, computing:
   *
   *   r = r + d
   *     = 0x86 + 0x83
   *     = 0x09 mod B
   */
  q1 += 1;

  r0 = u0 - q1 * d;

  if (r0 > q0) {
    q1 -= 1;
    r0 += d;
  }

  if (UNLIKELY(r0 >= d)) {
    q1 += 1;
    r0 -= d;
  }

  *q = q1;
  *r = r0;
}

/*
 * Division Engine
 */

#define mpn_divmod_init(den, nn, dp, dn) \
  (den)->up = mp_alloc_vla((nn) + 1);    \
  (den)->vp = mp_alloc_vla(dn);          \
  mpn_divmod_precomp(den, dp, dn)

#define mpn_divmod_clear(den, nn, dn) \
  mp_free_vla((den)->up, (nn) + 1);   \
  mp_free_vla((den)->vp, dn)

static void
mpn_divmod_precomp(mp_divisor_t *den, const mp_limb_t *dp, int dn) {
  int shift;

  if (dn <= 0 || dp[dn - 1] == 0)
    torsion_abort(); /* LCOV_EXCL_LINE */

  shift = mp_clz(dp[dn - 1]);

  if (dn == 1) {
    den->vp[0] = dp[0] << shift;
  } else {
    if (shift != 0)
      mpn_lshift(den->vp, dp, dn, shift);
    else
      mpn_copy(den->vp, dp, dn);
  }

  den->inv = mp_inv_2by1(den->vp[dn - 1]);
  den->shift = shift;
  den->size = dn;
}

static void
mpn_divmod_small(mp_limb_t *qp, mp_limb_t *rp,
                 const mp_limb_t *np, int nn,
                 const mp_divisor_t *den) {
  mp_limb_t d = den->vp[0];
  mp_limb_t m = den->inv;
  mp_limb_t q, n1, n0;
  mp_limb_t r = 0;
  int s = den->shift;
  int j;

  for (j = nn - 1; j >= 0; j--) {
    n1 = r;
    n0 = np[j];

    if (s != 0) {
      n1 = (n1 << s) | (n0 >> (MP_LIMB_BITS - s));
      n0 <<= s;
    }

    mp_div_2by1(&q, &r, n1, n0, d, m);

    r >>= s;

    if (qp != NULL)
      qp[j] = q;
  }

  if (rp != NULL)
    rp[0] = r;
}

static void
mpn_divmod_inner(mp_limb_t *qp, mp_limb_t *rp,
                 const mp_limb_t *np, int nn,
                 mp_divisor_t *den) {
  /* Division of nonnegative integers.
   *
   * [KNUTH] Algorithm D, Page 272, Section 4.3.1.
   *
   * Originally based on the Hacker's Delight
   * `divmnu64` function, the code below has
   * taken on some modifications based on the
   * golang logic.
   */
  const mp_limb_t *vp = den->vp;
  mp_limb_t *up = den->up;
  mp_limb_t m = den->inv;
  mp_limb_t qhat, rhat;
  mp_limb_t c, hi, lo;
  int dn = den->size;
  int j;

  if (nn < dn)
    torsion_abort(); /* LCOV_EXCL_LINE */

  if (dn == 1) {
    mpn_divmod_small(qp, rp, np, nn, den);
    return;
  }

  if (den->shift != 0) {
    up[nn] = mpn_lshift(up, np, nn, den->shift);
  } else {
    mpn_copy(up, np, nn);
    up[nn] = 0;
  }

  for (j = nn - dn; j >= 0; j--) {
    /* Compute estimate qhat of qp[j]. */
    qhat = MP_LIMB_MAX;

    if (up[j + dn] != vp[dn - 1]) {
      mp_div_2by1(&qhat, &rhat, up[j + dn], up[j + dn - 1], vp[dn - 1], m);

      mp_mul(hi, lo, qhat, vp[dn - 2]);

      while (mp_gt_2(hi, lo, rhat, up[j + dn - 2])) {
        qhat -= 1;
        rhat += vp[dn - 1];

        if (rhat < vp[dn - 1])
          break;

        mp_mul(hi, lo, qhat, vp[dn - 2]);
      }
    }

    /* Multiply and subtract. */
    c = mpn_submul_1(up + j, vp, dn, qhat);

    mp_sub(up[j + dn], c, up[j + dn], c);

    /* Correct off-by-one error. */
    if (c != 0) {
      up[j + dn] += mpn_add_n(up + j, up + j, vp, dn);

      qhat -= 1;
    }

    if (qp != NULL)
      qp[j] = qhat;
  }

  /* Unnormalize. */
  if (rp != NULL) {
    if (den->shift != 0)
      mpn_rshift(rp, up, dn, den->shift);
    else
      mpn_copy(rp, up, dn);
  }
}

static TORSION_INLINE void
mpn_mod_inner(mp_limb_t *rp, const mp_limb_t *np, int nn, mp_divisor_t *den) {
  nn = mpn_strip(np, nn);

  if (nn > den->size)
    mpn_divmod_inner(NULL, rp, np, nn, den);
  else
    mpn_copy(rp, np, den->size);
}

/*
 * Division
 */

mp_limb_t
mpn_divmod_1(mp_limb_t *qp, const mp_limb_t *np, int nn, mp_limb_t d) {
  mp_limb_t q, r, n0, n1, m;
  int i, s;

  if (nn <= 0 || d == 0)
    torsion_abort(); /* LCOV_EXCL_LINE */

  if (nn == 1) {
    q = np[0] / d;
    r = np[0] - q * d;

    if (qp != NULL)
      qp[0] = q;

    return r;
  }

  r = 0;
  s = mp_clz(d);
  m = mp_inv_2by1(d);

  d <<= s;

  for (i = nn - 1; i >= 0; i--) {
    n1 = r;
    n0 = np[i];

    if (s != 0) {
      n1 = (n1 << s) | (n0 >> (MP_LIMB_BITS - s));
      n0 <<= s;
    }

    mp_div_2by1(&q, &r, n1, n0, d, m);

    r >>= s;

    if (qp != NULL)
      qp[i] = q;
  }

  return r;
}

void
mpn_div_1(mp_limb_t *qp, const mp_limb_t *np, int nn, mp_limb_t d) {
  mpn_divmod_1(qp, np, nn, d);
}

mp_limb_t
mpn_mod_1(const mp_limb_t *np, int nn, mp_limb_t d) {
  return mpn_divmod_1(NULL, np, nn, d);
}

mp_wide_t
mpn_mod_2(const mp_limb_t *np, int nn, mp_wide_t d) {
  mp_limb_t dp[2];
  mp_limb_t rp[2];
  int dn;

  dp[0] = d;
  dp[1] = d >> MP_LIMB_BITS;

  rp[0] = 0;
  rp[1] = 0;

  dn = mpn_strip(dp, 2);

  if (nn >= dn)
    mpn_mod(rp, np, nn, dp, dn);
  else
    mpn_copy(rp, np, nn);

  return ((mp_wide_t)rp[1] << MP_LIMB_BITS) | rp[0];
}

void
mpn_divmod(mp_limb_t *qp, mp_limb_t *rp,
           const mp_limb_t *np, int nn,
           const mp_limb_t *dp, int dn) {
  mp_divisor_t den;

  if (dn <= 0 || nn < dn)
    torsion_abort(); /* LCOV_EXCL_LINE */

  mpn_divmod_init(&den, nn, dp, dn);
  mpn_divmod_inner(qp, rp, np, nn, &den);
  mpn_divmod_clear(&den, nn, dn);
}

void
mpn_div(mp_limb_t *qp, const mp_limb_t *np, int nn,
                       const mp_limb_t *dp, int dn) {
  mpn_divmod(qp, NULL, np, nn, dp, dn);
}

void
mpn_mod(mp_limb_t *rp, const mp_limb_t *np, int nn,
                       const mp_limb_t *dp, int dn) {
  mpn_divmod(NULL, rp, np, nn, dp, dn);
}

/*
 * Left Shift
 */

mp_limb_t
mpn_lshift(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits) {
  mp_limb_t c = 0;
  mp_limb_t w;
  int i;

  ASSERT(bits > 0 && bits < MP_LIMB_BITS);

  for (i = 0; i < xn; i++) {
    w = xp[i];
    zp[i] = (w << bits) | c;
    c = w >> (MP_LIMB_BITS - bits);
  }

  return c;
}

/*
 * Right Shift
 */

mp_limb_t
mpn_rshift(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits) {
  mp_limb_t c = 0;
  mp_limb_t w;
  int i;

  ASSERT(bits > 0 && bits < MP_LIMB_BITS);

  for (i = xn - 1; i >= 0; i--) {
    w = xp[i];
    zp[i] = c | (w >> bits);
    c = w << (MP_LIMB_BITS - bits);
  }

  return c >> (MP_LIMB_BITS - bits);
}

/*
 * Bit Manipulation
 */

mp_limb_t
mpn_get_bit(const mp_limb_t *xp, int xn, int pos) {
  int index = pos / MP_LIMB_BITS;

  if (index >= xn)
    return 0;

  return (xp[index] >> (pos % MP_LIMB_BITS)) & 1;
}

mp_limb_t
mpn_get_bits(const mp_limb_t *xp, int xn, int pos, int width) {
  int index = pos / MP_LIMB_BITS;
  int shift;
  mp_limb_t bits;

  if (index >= xn)
    return 0;

  shift = pos % MP_LIMB_BITS;
  bits = (xp[index] >> shift) & ((MP_LIMB_C(1) << width) - 1);

  if (shift + width > MP_LIMB_BITS && index + 1 < xn) {
    int more = shift + width - MP_LIMB_BITS;
    mp_limb_t next = xp[index + 1] & ((MP_LIMB_C(1) << more) - 1);

    bits |= next << (MP_LIMB_BITS - shift);
  }

  return bits;
}

/*
 * Number Theoretic Functions
 */

int
mpn_invert(mp_limb_t *zp,
           const mp_limb_t *xp, int xn,
           const mp_limb_t *yp, int yn,
           mp_limb_t *scratch) {
  /* Penk's right shift binary EGCD.
   *
   * [KNUTH] Exercise 4.5.2.39, Page 646.
   */
  mp_limb_t *ap = &scratch[0 * (yn + 1)];
  mp_limb_t *bp = &scratch[1 * (yn + 1)];
  mp_limb_t *up = &scratch[2 * (yn + 1)];
  mp_limb_t *vp = &scratch[3 * (yn + 1)];
  int an, bn, un, vn, shift;

  if (!mpn_odd_p(yp, yn) || xn > yn)
    torsion_abort(); /* LCOV_EXCL_LINE */

  if (mpv_cmp_1(yp, yn, 1) == 0) {
    mpn_zero(zp, yn);
    return 0;
  }

  an = mpv_set(ap, xp, xn);
  bn = mpv_set(bp, yp, yn);
  un = mpv_set_1(up, 1);
  vn = mpv_set_1(vp, 0);

  while (an != 0) {
    shift = mpn_ctz(ap, an);
    an = mpv_rshift(ap, ap, an, shift);

    while (shift--) {
      if (mpn_odd_p(up, un))
        un = mpv_add(up, up, un, yp, yn);

      un = mpv_rshift(up, up, un, 1);
    }

    shift = mpn_ctz(bp, bn);
    bn = mpv_rshift(bp, bp, bn, shift);

    while (shift--) {
      if (mpn_odd_p(vp, vn))
        vn = mpv_add(vp, vp, vn, yp, yn);

      vn = mpv_rshift(vp, vp, vn, 1);
    }

    if (mpv_cmp(ap, an, bp, bn) >= 0) {
      an = mpv_sub(ap, ap, an, bp, bn);
      un = mpv_sub_mod(up, up, un, vp, vn, yp, yn);
    } else {
      bn = mpv_sub(bp, bp, bn, ap, an);
      vn = mpv_sub_mod(vp, vp, vn, up, un, yp, yn);
    }

    ASSERT(un <= yn);
    ASSERT(vn <= yn);
  }

  if (mpv_cmp_1(bp, bn, 1) != 0) {
    mpn_zero(zp, yn);
    return 0;
  }

  ASSERT(mpv_cmp(vp, vn, yp, yn) < 0);

  mpn_copy(zp, vp, vn);
  mpn_zero(zp + vn, yn - vn);

  return 1;
}

int
mpn_invert_n(mp_limb_t *zp,
             const mp_limb_t *xp,
             const mp_limb_t *yp,
             int n,
             mp_limb_t *scratch) {
  int xn = mpn_strip(xp, n);
  int yn = n;

  ASSERT(n > 0);

  return mpn_invert(zp, xp, xn, yp, yn, scratch);
}

int
mpn_jacobi(const mp_limb_t *xp, int xn,
           const mp_limb_t *yp, int yn,
           mp_limb_t *scratch) {
  /* Binary Jacobi Symbol.
   *
   * [JACOBI] Page 3, Section 3.
   */
  mp_limb_t *ap = &scratch[0 * yn];
  mp_limb_t *bp = &scratch[1 * yn];
  int an, bn, bits;
  int j = 1;

  if (!mpn_odd_p(yp, yn) || xn > yn)
    torsion_abort(); /* LCOV_EXCL_LINE */

  an = mpv_set(ap, xp, xn);
  bn = mpv_set(bp, yp, yn);

  while (an != 0) {
    bits = mpn_ctz(ap, an);
    an = mpv_rshift(ap, ap, an, bits);

    ASSERT(bn > 0);

    if (bits & 1) {
      if ((bp[0] & 7) == 3 || (bp[0] & 7) == 5)
        j = -j;
    }

    if (mpv_cmp(ap, an, bp, bn) < 0) {
      mpn_swap(&ap, &an, &bp, &bn);

      if ((ap[0] & 3) == 3 && (bp[0] & 3) == 3)
        j = -j;
    }

    an = mpv_sub(ap, ap, an, bp, bn);
    an = mpv_rshift(ap, ap, an, 1);

    if ((bp[0] & 7) == 3 || (bp[0] & 7) == 5)
      j = -j;
  }

  if (mpv_cmp_1(bp, bn, 1) != 0)
    return 0;

  return j;
}

int
mpn_jacobi_n(const mp_limb_t *xp,
             const mp_limb_t *yp,
             int n,
             mp_limb_t *scratch) {
  int xn = mpn_strip(xp, n);
  int yn = n;

  ASSERT(n > 0);

  return mpn_jacobi(xp, xn, yp, yn, scratch);
}

static void
mpn_div_powm(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                            const mp_limb_t *yp, int yn,
                            const mp_limb_t *mp, int mn,
                            mp_limb_t *scratch) {
  /* Sliding window with division. */
  mp_limb_t *ap = &scratch[0 * mn]; /* mn */
  mp_limb_t *rp = &scratch[1 * mn]; /* mn */
  mp_limb_t *sp = &scratch[2 * mn]; /* 2 * mn */
  mp_limb_t *tp = &scratch[4 * mn]; /* 2 * mn */
  mp_limb_t *wp = &scratch[6 * mn]; /* wnd_size * mn */
  int i, j, len, width, bits, shift;
  mp_divisor_t den;
  int sn = mn * 2;

  if (mn <= 0 || xn > mn)
    torsion_abort(); /* LCOV_EXCL_LINE */

  mpn_copy(ap, xp, xn);
  mpn_zero(ap + xn, mn - xn);

  mpn_divmod_init(&den, sn, mp, mn);

  len = mpn_bitlen(yp, yn);

  ASSERT(len > 0);

  if (yn > 2 && len >= MP_SLIDE_WIDTH) {
    mpn_sqr(sp, ap, mn, tp);
    mpn_mod_inner(rp, sp, sn, &den);

#define WND(i) &wp[(i) * mn]

    mpn_copy(WND(0), ap, mn);

    for (i = 1; i < MP_SLIDE_SIZE; i++) {
      mpn_mul_n(sp, WND(i - 1), rp, mn);
      mpn_mod_inner(WND(i), sp, sn, &den);
    }

    i = len;

    while (i >= MP_SLIDE_WIDTH) {
      width = MP_SLIDE_WIDTH;
      bits = mpn_get_bits(yp, yn, i - width, width);

      if (bits < MP_SLIDE_SIZE) {
        mpn_sqr(sp, rp, mn, tp);
        mpn_mod_inner(rp, sp, sn, &den);
        i -= 1;
        continue;
      }

      shift = mp_ctz(bits);
      width -= shift;
      bits >>= shift;

      if (i == len) {
        mpn_copy(rp, WND(bits >> 1), mn);
      } else {
        for (j = 0; j < width; j++) {
          mpn_sqr(sp, rp, mn, tp);
          mpn_mod_inner(rp, sp, sn, &den);
        }

        mpn_mul_n(sp, rp, WND(bits >> 1), mn);
        mpn_mod_inner(rp, sp, sn, &den);
      }

#undef WND

      i -= width;
    }
  } else {
    mpn_copy(rp, ap, mn);

    i = len - 1;
  }

  for (i -= 1; i >= 0; i--) {
    mpn_sqr(sp, rp, mn, tp);
    mpn_mod_inner(rp, sp, sn, &den);

    if (mpn_get_bit(yp, yn, i)) {
      mpn_mul_n(sp, rp, ap, mn);
      mpn_mod_inner(rp, sp, sn, &den);
    }
  }

  if (mpn_cmp(rp, mp, mn) >= 0)
    mpn_divmod_inner(NULL, zp, rp, mn, &den);
  else
    mpn_copy(zp, rp, mn);

  mpn_divmod_clear(&den, sn, mn);
}

static void
mpn_mont_powm(mp_limb_t *zp,
              const mp_limb_t *xp, int xn,
              const mp_limb_t *yp, int yn,
              const mp_limb_t *mp, int mn,
              mp_limb_t *scratch) {
  /* Sliding window with montgomery. */
  mp_limb_t *ap = &scratch[0 * mn]; /* mn */
  mp_limb_t *rp = &scratch[1 * mn]; /* mn */
  mp_limb_t *tp = &scratch[2 * mn]; /* 2 * mn + 1 */
  mp_limb_t *rr = &scratch[4 * mn + 1]; /* mn */
  mp_limb_t *wp = &scratch[5 * mn + 1]; /* wnd_size * mn */
  int i, j, len, width, bits, shift;
  mp_limb_t k;

  if (!mpn_odd_p(mp, mn))
    torsion_abort(); /* LCOV_EXCL_LINE */

  len = mpn_bitlen(yp, yn);

  ASSERT(len > 0);

  mpn_copy(ap, xp, xn);
  mpn_zero(ap + xn, mn - xn);

  mpn_mont(&k, rr, mp, mn, tp);

  mpn_montmul_var(ap, ap, rr, mp, mn, k, tp);

  if (yn > 2 && len >= MP_SLIDE_WIDTH) {
    mpn_montmul_var(rp, ap, ap, mp, mn, k, tp);

#define WND(i) &wp[(i) * mn]

    mpn_copy(WND(0), ap, mn);

    for (i = 1; i < MP_SLIDE_SIZE; i++)
      mpn_montmul_var(WND(i), WND(i - 1), rp, mp, mn, k, tp);

    i = len;

    while (i >= MP_SLIDE_WIDTH) {
      width = MP_SLIDE_WIDTH;
      bits = mpn_get_bits(yp, yn, i - width, width);

      if (bits < MP_SLIDE_SIZE) {
        mpn_montmul_var(rp, rp, rp, mp, mn, k, tp);
        i -= 1;
        continue;
      }

      shift = mp_ctz(bits);
      width -= shift;
      bits >>= shift;

      if (i == len) {
        mpn_copy(rp, WND(bits >> 1), mn);
      } else {
        for (j = 0; j < width; j++)
          mpn_montmul_var(rp, rp, rp, mp, mn, k, tp);

        mpn_montmul_var(rp, rp, WND(bits >> 1), mp, mn, k, tp);
      }

#undef WND

      i -= width;
    }
  } else {
    mpn_copy(rp, ap, mn);

    i = len - 1;
  }

  for (i -= 1; i >= 0; i--) {
    mpn_montmul_var(rp, rp, rp, mp, mn, k, tp);

    if (mpn_get_bit(yp, yn, i))
      mpn_montmul_var(rp, rp, ap, mp, mn, k, tp);
  }

  mpn_set_1(rr, mn, 1);
  mpn_montmul_var(rp, rp, rr, mp, mn, k, tp);

  if (mpn_cmp(rp, mp, mn) >= 0) {
    mpn_sub_n(rp, rp, mp, mn);

    if (mpn_cmp(rp, mp, mn) >= 0)
      mpn_mod(rp, rp, mn, mp, mn);
  }

  mpn_copy(zp, rp, mn);
}

void
mpn_powm(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                        const mp_limb_t *yp, int yn,
                        const mp_limb_t *mp, int mn,
                        mp_limb_t *scratch) {
  /* x^y mod 0 = abort */
  if (mn <= 0 || xn > mn || mp[mn - 1] == 0)
    torsion_abort(); /* LCOV_EXCL_LINE */

  /* x^y mod 1 = 0 */
  if (mn == 1 && mp[0] == 1) {
    mpn_zero(zp, mn);
    return;
  }

  /* x^0 mod m = 1 */
  if (yn == 0) {
    mpn_set_1(zp, mn, 1);
    return;
  }

  /* 0^y mod m = 0 */
  if (xn == 0) {
    mpn_zero(zp, mn);
    return;
  }

  if (yn > 1 && (mp[0] & 1) != 0) {
    /* Montgomery multiplication. */
    mpn_mont_powm(zp, xp, xn, yp, yn, mp, mn, scratch);
  } else {
    /* Division (faster for smaller exponents). */
    mpn_div_powm(zp, xp, xn, yp, yn, mp, mn, scratch);
  }
}

void
mpn_sec_powm(mp_limb_t *zp,
             const mp_limb_t *xp, int xn,
             const mp_limb_t *yp, int yn,
             const mp_limb_t *mp, int mn,
             mp_limb_t *scratch) {
  /* Fixed window montgomery. */
  mp_limb_t *rp = &scratch[0 * mn]; /* mn */
  mp_limb_t *tp = &scratch[1 * mn]; /* 2 * mn + 1 */
  mp_limb_t *sp = &scratch[3 * mn + 1]; /* mn */
  mp_limb_t *rr = &scratch[4 * mn + 1]; /* mn */
  mp_limb_t *wp = &scratch[5 * mn + 1]; /* wnd_size * mn */
  int i, j, b, steps;
  mp_limb_t k;

  if (!mpn_odd_p(mp, mn) || xn > mn)
    torsion_abort(); /* LCOV_EXCL_LINE */

  mpn_copy(rp, xp, xn);
  mpn_zero(rp + xn, mn - xn);

  mpn_mont(&k, rr, mp, mn, tp);

#define WND(i) &wp[(i) * mn]

  mpn_set_1(WND(0), mn, 1);
  mpn_montmul(WND(0), WND(0), rr, mp, mn, k, tp);
  mpn_montmul(WND(1), rp, rr, mp, mn, k, tp);

  for (i = 2; i < MP_FIXED_SIZE; i++)
    mpn_montmul(WND(i), WND(i - 1), WND(1), mp, mn, k, tp);

  steps = ((yn * MP_LIMB_BITS) + MP_FIXED_WIDTH - 1) / MP_FIXED_WIDTH;

  mpn_copy(rp, WND(0), mn);
  mpn_zero(sp, mn);

  for (i = steps - 1; i >= 0; i--) {
    b = mpn_get_bits(yp, yn, i * MP_FIXED_WIDTH, MP_FIXED_WIDTH);

    for (j = 0; j < MP_FIXED_SIZE; j++)
      mpn_select(sp, sp, WND(j), mn, j == b);

    if (i == steps - 1) {
      mpn_copy(rp, sp, mn);
    } else {
      for (j = 0; j < MP_FIXED_WIDTH; j++)
        mpn_montmul(rp, rp, rp, mp, mn, k, tp);

      mpn_montmul(rp, rp, sp, mp, mn, k, tp);
    }
  }

#undef WND

  mpn_set_1(rr, mn, 1);
  mpn_montmul(zp, rp, rr, mp, mn, k, tp);
}

/*
 * Helpers
 */

int
mpn_strip(const mp_limb_t *xp, int xn) {
  while (xn > 0 && xp[xn - 1] == 0)
    xn -= 1;

  return xn;
}

int
mpn_odd_p(const mp_limb_t *xp, int xn) {
  return xn > 0 && (xp[0] & 1) != 0;
}

int
mpn_even_p(const mp_limb_t *xp, int xn) {
  return !mpn_odd_p(xp, xn);
}

int
mpn_ctz(const mp_limb_t *xp, int xn) {
  int i;

  for (i = 0; i < xn; i++) {
    if (xp[i] != 0)
      return i * MP_LIMB_BITS + mp_ctz(xp[i]);
  }

  return xn * MP_LIMB_BITS;
}

int
mpn_bitlen(const mp_limb_t *xp, int xn) {
  int i;

  for (i = xn - 1; i >= 0; i--) {
    if (xp[i] != 0)
      return i * MP_LIMB_BITS + mp_bitlen(xp[i]);
  }

  return 0;
}

size_t
mpn_bytelen(const mp_limb_t *xp, int xn) {
  return (mpn_bitlen(xp, xn) + 7) / 8;
}

void
mpn_swap(mp_limb_t **xp, int *xn,
         mp_limb_t **yp, int *yn) {
  mp_limb_t *tp = *xp;
  int tn = *xn;

  *xp = *yp; *xn = *yn;
  *yp =  tp; *yn =  tn;
}

/*
 * Constant Time
 */

void
mpn_select(mp_limb_t *zp,
           const mp_limb_t *xp,
           const mp_limb_t *yp,
           int n, int flag) {
  mp_limb_t cond = (flag != 0);
  mp_limb_t mask0 = mp_limb_barrier(cond - 1);
  mp_limb_t mask1 = mp_limb_barrier(~mask0);
  int i;

  for (i = 0; i < n; i++)
    zp[i] = (xp[i] & mask0) | (yp[i] & mask1);
}

void
mpn_select_zero(mp_limb_t *zp, const mp_limb_t *xp, int n, int flag) {
  mp_limb_t cond = (flag != 0);
  mp_limb_t mask = mp_limb_barrier(cond - 1);
  int i;

  for (i = 0; i < n; i++)
    zp[i] = xp[i] & mask;
}

int
mpn_sec_zero_p(const mp_limb_t *xp, int xn) {
  /* Compute (x == y) in constant time. */
  mp_limb_t w = 0;
  int i;

  for (i = 0; i < xn; i++)
    w |= xp[i];

  w = (w >> 1) | (w & 1);

  return (w - 1) >> (MP_LIMB_BITS - 1);
}

int
mpn_sec_equal(const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  /* Compute (x == y) in constant time. */
  mp_limb_t w = 0;
  int i;

  for (i = 0; i < n; i++)
    w |= xp[i] ^ yp[i];

  w = (w >> 1) | (w & 1);

  return (w - 1) >> (MP_LIMB_BITS - 1);
}

static int
mpn_sec_compare(const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  /* Compare in constant time. */
  mp_limb_t eq = 1;
  mp_limb_t lt = 0;
  mp_limb_t a, b;
  int i = n * 2;

  while (i--) {
    a = (xp[i / 2] >> ((i % 2) * MP_LOW_BITS)) & MP_LOW_MASK;
    b = (yp[i / 2] >> ((i % 2) * MP_LOW_BITS)) & MP_LOW_MASK;
    lt |= eq & ((a - b) >> (MP_LIMB_BITS - 1));
    eq &= ((a ^ b) - 1) >> (MP_LIMB_BITS - 1);
  }

  return (lt << 1) | eq;
}

int
mpn_sec_cmp(const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  /* Compute mpn_cmp(x, y) in constant time. */
  int cmp = mpn_sec_compare(xp, yp, n);
  int lt = cmp >> 1;
  int eq = cmp & 1;

  return (1 - 2 * lt) * (1 - eq);
}

int
mpn_sec_lt(const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  /* Compute (x < y) in constant time. */
  int cmp = mpn_sec_compare(xp, yp, n);
  int lt = cmp >> 1;
  int eq = cmp & 1;

  return lt & (eq ^ 1);
}

int
mpn_sec_lte(const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  /* Compute (x <= y) in constant time. */
  int cmp = mpn_sec_compare(xp, yp, n);
  int lt = cmp >> 1;
  int eq = cmp & 1;

  return lt | eq;
}

int
mpn_sec_gt(const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  /* Compute (x > y) in constant time. */
  int cmp = mpn_sec_compare(xp, yp, n);
  int lt = cmp >> 1;
  int eq = cmp & 1;

  return (lt | eq) ^ 1;
}

int
mpn_sec_gte(const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  /* Compute (x >= y) in constant time. */
  int cmp = mpn_sec_compare(xp, yp, n);
  int lt = cmp >> 1;
  int eq = cmp & 1;

  return (lt ^ 1) | eq;
}

/*
 * Import
 */

void
mpn_import(mp_limb_t *zp, int zn,
           const unsigned char *raw,
           size_t len, int endian) {
  int size = mp_cast_size(len);
  int i, j, k;

  CHECK(endian == 1 || endian == -1);

  if (endian == 1) {
    k = size - 1;

    for (i = 0; i < zn && k >= 0; i++) {
      zp[i] = 0;
      for (j = 0; j < MP_LIMB_BYTES && k >= 0; j++)
        zp[i] |= (mp_limb_t)raw[k--] << (j * 8);
    }
  } else {
    k = 0;

    for (i = 0; i < zn && k < size; i++) {
      zp[i] = 0;
      for (j = 0; j < MP_LIMB_BYTES && k < size; j++)
        zp[i] |= (mp_limb_t)raw[k++] << (j * 8);
    }
  }

  while (i < zn)
    zp[i++] = 0;
}

/*
 * Export
 */

void
mpn_export(unsigned char *raw, size_t len,
           const mp_limb_t *xp, int xn, int endian) {
  int size = mp_cast_size(len);
  int i, j, k;

  CHECK(endian == 1 || endian == -1);

  if (endian == 1) {
    k = size - 1;

    for (i = 0; i < xn && k >= 0; i++) {
      for (j = 0; j < MP_LIMB_BYTES && k >= 0; j++)
        raw[k--] = (xp[i] >> (j * 8)) & 0xff;
    }

    while (k >= 0)
      raw[k--] = 0;
  } else {
    k = 0;

    for (i = 0; i < xn && k < size; i++) {
      for (j = 0; j < MP_LIMB_BYTES && k < size; j++)
        raw[k++] = (xp[i] >> (j * 8)) & 0xff;
    }

    while (k < size)
      raw[k++] = 0;
  }
}

/*
 * MPV Interface
 */

/*
 * Assignment
 */

static TORSION_INLINE int
mpv_set_1(mp_limb_t *xp, mp_limb_t y) {
  xp[0] = y;
  return y != 0;
}

static TORSION_INLINE int
mpv_set(mp_limb_t *zp, const mp_limb_t *xp, int xn) {
  mpn_copy(zp, xp, xn);
  return xn;
}

/*
 * Comparison
 */

static TORSION_INLINE int
mpv_cmp_1(const mp_limb_t *xp, int xn, mp_limb_t y) {
  mp_limb_t x;

  if (xn > 1)
    return 1;

  x = xn > 0 ? xp[0] : 0;

  if (x != y)
    return x < y ? -1 : 1;

  return 0;
}

static TORSION_INLINE int
mpv_cmp(const mp_limb_t *xp, int xn,
        const mp_limb_t *yp, int yn) {
  if (xn != yn)
    return xn < yn ? -1 : 1;

  return mpn_cmp(xp, yp, xn);
}

/*
 * Addition
 */

static TORSION_INLINE int
mpv_add_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y) {
  zp[xn] = mpn_add_1(zp, xp, xn, y);
  return xn + (zp[xn] != 0);
}

static TORSION_INLINE int
mpv_add(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                       const mp_limb_t *yp, int yn) {
  int n = MP_MAX(xn, yn);

  if (xn >= yn)
    zp[n] = mpn_add(zp, xp, xn, yp, yn);
  else
    zp[n] = mpn_add(zp, yp, yn, xp, xn);

  return n + (zp[n] != 0);
}

/*
 * Subtraction
 */

static TORSION_INLINE int
mpv_sub_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y) {
  CHECK(mpn_sub_1(zp, xp, xn, y) == 0);
  return mpn_strip(zp, xn);
}

static TORSION_INLINE int
mpv_sub(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                       const mp_limb_t *yp, int yn) {
  CHECK(mpn_sub(zp, xp, xn, yp, yn) == 0);
  return mpn_strip(zp, xn);
}

static TORSION_INLINE int
mpv_sub_mod(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                           const mp_limb_t *yp, int yn,
                           const mp_limb_t *mp, int mn) {
  int zn;

  if (mpv_cmp(xp, xn, yp, yn) >= 0) {
    /* z = x - y */
    zn = mpv_sub(zp, xp, xn, yp, yn);
  } else {
    /* z = m - (y - x) */
    zn = mpv_sub(zp, yp, yn, xp, xn);
    zn = mpv_sub(zp, mp, mn, zp, zn);
  }

  return zn;
}

/*
 * Multiplication
 */

static TORSION_INLINE int
mpv_mul_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y) {
  zp[xn] = mpn_mul_1(zp, xp, xn, y);
  return mpn_strip(zp, xn + 1);
}

static TORSION_INLINE int
mpv_mul(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                       const mp_limb_t *yp, int yn) {
  mpn_mul(zp, xp, xn, yp, yn);
  return mpn_strip(zp, xn + yn);
}

static TORSION_INLINE int
mpv_sqr(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t *scratch) {
  mpn_sqr(zp, xp, xn, scratch);
  return mpn_strip(zp, xn * 2);
}

/*
 * Left Shift
 */

static TORSION_INLINE int
mpv_lshift(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits) {
  int s = bits / MP_LIMB_BITS;
  int r = bits % MP_LIMB_BITS;
  int i, zn;

  if (xn == 0)
    return 0;

  if (r != 0) {
    zp[xn] = mpn_lshift(zp, xp, xn, r);
    zn = xn + (zp[xn] != 0);
  } else if (zp != xp) {
    zn = mpv_set(zp, xp, xn);
  } else {
    zn = xn;
  }

  if (s != 0) {
    for (i = zn - 1; i >= 0; i--)
      zp[i + s] = zp[i];

    for (i = 0; i < s; i++)
      zp[i] = 0;

    zn += s;
  }

  return mpn_strip(zp, zn);
}

/*
 * Right Shift
 */

static TORSION_INLINE int
mpv_rshift(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits) {
  int b = MP_MIN(bits, xn * MP_LIMB_BITS);
  int s = b / MP_LIMB_BITS;
  int r = b % MP_LIMB_BITS;
  int i, zn;

  if (s != 0) {
    zn = xn - s;

    for (i = 0; i < zn; i++)
      zp[i] = xp[i + s];
  } else if (zp != xp) {
    zn = mpv_set(zp, xp, xn);
  } else {
    zn = xn;
  }

  if (r != 0)
    mpn_rshift(zp, zp, zn, r);

  return mpn_strip(zp, zn);
}

/*
 * MPZ Interface
 */

/*
 * Initialization
 */

void
mpz_init(mpz_t x) {
  x->limbs = mp_alloc_limbs(1);
  x->limbs[0] = 0;
  x->alloc = 1;
  x->size = 0;
}

/*
 * Uninitialization
 */

void
mpz_clear(mpz_t x) {
  if (x->alloc > 0)
    mp_free_limbs(x->limbs);

  x->limbs = NULL;
  x->alloc = 0;
  x->size = 0;
}

void
mpz_cleanse(mpz_t x) {
  if (x->alloc > 0)
    mpn_cleanse(x->limbs, x->alloc);

  mpz_clear(x);
}

/*
 * Internal
 */

static void
mpz_grow(mpz_t x, int size) {
  CHECK(size <= MP_SIZE_MAX);

  if (size > x->alloc) {
    x->limbs = mp_realloc_limbs(x->limbs, size);
    x->alloc = size;
  }
}

/*
 * Assignment
 */

void
mpz_set(mpz_t z, const mpz_t x) {
  if (z != x) {
    int xn = MP_ABS(x->size);

    mpz_grow(z, xn);

    mpn_copy(z->limbs, x->limbs, xn);

    z->size = x->size;
  }
}

void
mpz_roset(mpz_t z, const mpz_t x) {
  z->limbs = (mp_limb_t *)x->limbs;
  z->alloc = 0;
  z->size = x->size;
}

void
mpz_set_ui(mpz_t z, mp_limb_t x) {
  if (x == 0) {
    z->size = 0;
  } else {
    mpz_grow(z, 1);

    z->limbs[0] = x;
    z->size = 1;
  }
}

void
mpz_set_u64(mpz_t z, uint64_t x) {
#if MP_LIMB_BITS == 32
  if (x == 0) {
    z->size = 0;
  } else {
    mpz_grow(z, 2);

    z->limbs[0] = x;
    z->limbs[1] = x >> 32;
    z->size = mpn_strip(z->limbs, 2);
  }
#else
  mpz_set_ui(z, x);
#endif
}

/*
 * Conversion
 */

mp_limb_t
mpz_get_ui(const mpz_t x) {
  if (x->size == 0)
    return 0;

  return x->limbs[0];
}

uint64_t
mpz_get_u64(const mpz_t x) {
#if MP_LIMB_BITS == 32
  if (MP_ABS(x->size) < 2)
    return mpz_get_ui(x);

  return ((uint64_t)x->limbs[1] << 32) | x->limbs[0];
#else
  return mpz_get_ui(x);
#endif
}

/*
 * Comparison
 */

int
mpz_sgn(const mpz_t x) {
  if (x->size == 0)
    return 0;

  return x->size < 0 ? -1 : 1;
}

int
mpz_cmp(const mpz_t x, const mpz_t y) {
  int xs = x->size < 0;
  int ys = y->size < 0;
  int cmp;

  if (xs != ys)
    return ys - xs;

  cmp = mpz_cmpabs(x, y);

  return xs ? -cmp : cmp;
}

int
mpz_cmp_ui(const mpz_t x, mp_limb_t y) {
  if (x->size < 0)
    return -1;

  return mpz_cmpabs_ui(x, y);
}

/*
 * Unsigned Comparison
 */

int
mpz_cmpabs(const mpz_t x, const mpz_t y) {
  return mpv_cmp(x->limbs, MP_ABS(x->size),
                 y->limbs, MP_ABS(y->size));
}

int
mpz_cmpabs_ui(const mpz_t x, mp_limb_t y) {
  return mpv_cmp_1(x->limbs, MP_ABS(x->size), y);
}

/*
 * Addition
 */

void
mpz_add(mpz_t z, const mpz_t x, const mpz_t y) {
  int xn = MP_ABS(x->size);
  int yn = MP_ABS(y->size);
  int zn = MP_MAX(xn, yn) + 1;

  mpz_grow(z, zn);

  if ((x->size < 0) == (y->size < 0)) {
    /* x + y == x + y */
    /* (-x) + (-y) == -(x + y) */
    zn = mpv_add(z->limbs, x->limbs, xn, y->limbs, yn);
  } else {
    /* x + (-y) == x - y == -(y - x) */
    /* (-x) + y == y - x == -(x - y) */
    int cmp = mpz_cmpabs(x, y);

    /* x + (-x) == (-x) + x == 0 */
    if (cmp == 0) {
      z->size = 0;
      return;
    }

    if (cmp < 0)
      zn = -mpv_sub(z->limbs, y->limbs, yn, x->limbs, xn);
    else
      zn = mpv_sub(z->limbs, x->limbs, xn, y->limbs, yn);
  }

  z->size = x->size < 0 ? -zn : zn;
}

void
mpz_add_ui(mpz_t z, const mpz_t x, mp_limb_t y) {
  int xn = MP_ABS(x->size);
  int zn = MP_MAX(xn, 1) + 1;

  mpz_grow(z, zn);

  if (x->size >= 0) {
    /* x + y == x + y */
    /* (-x) + (-y) == -(x + y) */
    zn = mpv_add_1(z->limbs, x->limbs, xn, y);
  } else {
    /* x + (-y) == x - y == -(y - x) */
    /* (-x) + y == y - x == -(x - y) */
    if (xn == 1 && x->limbs[0] < y) {
      z->limbs[0] = y - x->limbs[0];
      zn = 1;
    } else {
      zn = mpv_sub_1(z->limbs, x->limbs, xn, y);
    }
  }

  z->size = x->size < 0 ? -zn : zn;
}

/*
 * Subtraction
 */

void
mpz_sub(mpz_t z, const mpz_t x, const mpz_t y) {
  int xn = MP_ABS(x->size);
  int yn = MP_ABS(y->size);
  int zn = MP_MAX(xn, yn) + 1;

  mpz_grow(z, zn);

  if ((x->size < 0) != (y->size < 0)) {
    /* x - (-y) == x + y */
    /* (-x) - y == -(x + y) */
    zn = mpv_add(z->limbs, x->limbs, xn, y->limbs, yn);
  } else {
    /* x - y == x - y == -(y - x) */
    /* (-x) - (-y) == y - x == -(x - y) */
    int cmp = mpz_cmpabs(x, y);

    /* x - x == 0 */
    if (cmp == 0) {
      z->size = 0;
      return;
    }

    if (cmp < 0)
      zn = -mpv_sub(z->limbs, y->limbs, yn, x->limbs, xn);
    else
      zn = mpv_sub(z->limbs, x->limbs, xn, y->limbs, yn);
  }

  z->size = x->size < 0 ? -zn : zn;
}

void
mpz_sub_ui(mpz_t z, const mpz_t x, mp_limb_t y) {
  int xn = MP_ABS(x->size);
  int zn = MP_MAX(xn, 1) + 1;

  mpz_grow(z, zn);

  if (x->size <= 0) {
    /* x - (-y) == x + y */
    /* (-x) - y == -(x + y) */
    zn = mpv_add_1(z->limbs, x->limbs, xn, y);
  } else {
    /* x - y == x - y == -(y - x) */
    /* (-x) - (-y) == y - x == -(x - y) */
    if (xn == 1 && x->limbs[0] < y) {
      z->limbs[0] = y - x->limbs[0];
      zn = -1;
    } else {
      zn = mpv_sub_1(z->limbs, x->limbs, xn, y);
    }
  }

  z->size = x->size < 0 ? -zn : zn;
}

/*
 * Multiplication
 */

void
mpz_mul(mpz_t z, const mpz_t x, const mpz_t y) {
  int xn, yn, zn, tn;
  mp_limb_t *tp;

  if (x == y) {
    mpz_sqr(z, x);
    return;
  }

  if (x->size == 0 || y->size == 0) {
    z->size = 0;
    return;
  }

  xn = MP_ABS(x->size);
  yn = MP_ABS(y->size);
  zn = xn + yn;

  mpz_grow(z, zn);

  if (xn == 1) {
    zn = mpv_mul_1(z->limbs, y->limbs, yn, x->limbs[0]);
  } else if (yn == 1) {
    zn = mpv_mul_1(z->limbs, x->limbs, xn, y->limbs[0]);
  } else if (z == x || z == y) {
    tn = zn;
    tp = mp_alloc_vla(tn);
    zn = mpv_mul(tp, x->limbs, xn, y->limbs, yn);

    mpn_copy(z->limbs, tp, zn);

    mp_free_vla(tp, tn);
  } else {
    zn = mpv_mul(z->limbs, x->limbs, xn, y->limbs, yn);
  }

  z->size = ((x->size < 0) ^ (y->size < 0)) ? -zn : zn;
}

void
mpz_mul_ui(mpz_t z, const mpz_t x, mp_limb_t y) {
  int xn, zn;

  if (x->size == 0 || y == 0) {
    z->size = 0;
    return;
  }

  xn = MP_ABS(x->size);

  mpz_grow(z, xn + 1);

  zn = mpv_mul_1(z->limbs, x->limbs, xn, y);

  z->size = x->size < 0 ? -zn : zn;
}

void
mpz_sqr(mpz_t z, const mpz_t x) {
  int xn, zn, tn;
  mp_limb_t *tp;

  if (x->size == 0) {
    z->size = 0;
    return;
  }

  xn = MP_ABS(x->size);
  zn = xn * 2;

  mpz_grow(z, zn);

  if (xn == 1) {
    mp_sqr(z->limbs[1], z->limbs[0], x->limbs[0]);
    zn -= (z->limbs[1] == 0);
  } else {
    tn = z == x ? zn * 2 : zn;
    tp = mp_alloc_vla(tn);

    if (z == x) {
      zn = mpv_sqr(tp, x->limbs, xn, tp + zn);

      mpn_copy(z->limbs, tp, zn);
    } else {
      zn = mpv_sqr(z->limbs, x->limbs, xn, tp);
    }

    mp_free_vla(tp, tn);
  }

  z->size = zn;
}

/*
 * Division Engine
 */

static void
mpz_div_inner(mpz_t q, mpz_t r, const mpz_t n, const mpz_t d, int euclid) {
  int nn = MP_ABS(n->size);
  int dn = MP_ABS(d->size);
  int qs = (n->size < 0) ^ (d->size < 0);
  int rs = n->size < 0;
  mp_limb_t *qp = NULL;
  mp_limb_t *rp = NULL;
  int qn = 0;
  int rn = 0;

  CHECK(q != r);
  CHECK(q != d);
  CHECK(r != d);

  if (dn == 0)
    torsion_abort(); /* LCOV_EXCL_LINE */

  if (nn == 0) {
    if (r != NULL)
      r->size = 0;

    if (q != NULL)
      q->size = 0;

    return;
  }

  if (mpz_cmpabs(n, d) < 0) {
    if (r != NULL) {
      mpz_set(r, n);
      rn = nn;
    }

    if (q != NULL)
      q->size = 0;
  } else {
    if (q != NULL) {
      qn = nn - dn + 1;
      mpz_grow(q, qn);
      qp = q->limbs;
    }

    if (r != NULL) {
      rn = dn;
      mpz_grow(r, rn);
      rp = r->limbs;
    }

    mpn_divmod(qp, rp, n->limbs, nn, d->limbs, dn);

    if (q != NULL)
      qn = mpn_strip(qp, qn);

    if (r != NULL)
      rn = mpn_strip(rp, rn);
  }

  if (q != NULL)
    q->size = qs ? -qn : qn;

  if (r != NULL)
    r->size = rs ? -rn : rn;

  if (euclid) {
    if (q != NULL) {
      CHECK(r != NULL);

      if (r->size < 0) {
        if (d->size < 0)
          mpz_add_ui(q, q, 1);
        else
          mpz_sub_ui(q, q, 1);
      }
    }

    if (r != NULL) {
      if (r->size < 0) {
        if (d->size < 0)
          mpz_sub(r, r, d);
        else
          mpz_add(r, r, d);
      }
    }
  }
}

static mp_limb_t
mpz_div_ui_inner(mpz_t q, const mpz_t n, mp_limb_t d, int euclid) {
  int nn = MP_ABS(n->size);
  int ns = n->size < 0;
  mp_limb_t *qp = NULL;
  mp_limb_t r;
  int qn = 0;

  if (d == 0)
    torsion_abort(); /* LCOV_EXCL_LINE */

  if (nn == 0) {
    if (q != NULL)
      q->size = 0;

    return 0;
  }

  if (mpz_cmpabs_ui(n, d) < 0) {
    r = n->limbs[0];

    if (q != NULL)
      q->size = 0;
  } else {
    if (q != NULL) {
      mpz_grow(q, nn);
      qp = q->limbs;
    }

    r = mpn_divmod_1(qp, n->limbs, nn, d);

    if (q != NULL)
      qn = mpn_strip(qp, nn);
  }

  if (q != NULL)
    q->size = ns ? -qn : qn;

  if (euclid) {
    if (q != NULL) {
      if (ns && r != 0)
        mpz_sub_ui(q, q, 1);
    }

    if (ns && r != 0)
      r = d - r;
  }

  return r;
}

/*
 * Truncation Division
 */

void
mpz_quorem(mpz_t q, mpz_t r, const mpz_t n, const mpz_t d) {
  mpz_div_inner(q, r, n, d, 0);
}

void
mpz_quo(mpz_t q, const mpz_t n, const mpz_t d) {
  mpz_div_inner(q, NULL, n, d, 0);
}

void
mpz_rem(mpz_t r, const mpz_t n, const mpz_t d) {
  mpz_div_inner(NULL, r, n, d, 0);
}

mp_limb_t
mpz_quo_ui(mpz_t q, const mpz_t n, mp_limb_t d) {
  return mpz_div_ui_inner(q, n, d, 0);
}

mp_limb_t
mpz_rem_ui(const mpz_t n, mp_limb_t d) {
  return mpz_div_ui_inner(NULL, n, d, 0);
}

/*
 * Euclidean Division
 */

void
mpz_divmod(mpz_t q, mpz_t r, const mpz_t n, const mpz_t d) {
  mpz_div_inner(q, r, n, d, 1);
}

void
mpz_div(mpz_t q, const mpz_t n, const mpz_t d) {
  mpz_div_inner(q, NULL, n, d, 1);
}

void
mpz_mod(mpz_t r, const mpz_t n, const mpz_t d) {
  mpz_div_inner(NULL, r, n, d, 1);
}

mp_limb_t
mpz_div_ui(mpz_t q, const mpz_t n, mp_limb_t d) {
  return mpz_div_ui_inner(q, n, d, 1);
}

mp_limb_t
mpz_mod_ui(const mpz_t n, mp_limb_t d) {
  return mpz_div_ui_inner(NULL, n, d, 1);
}

/*
 * Exact Division
 */

void
mpz_divexact(mpz_t q, const mpz_t n, const mpz_t d) {
  mpz_t r;

  mpz_init(r);

  mpz_div_inner(q, r, n, d, 0);

  CHECK(r->size == 0);

  mpz_clear(r);
}

void
mpz_divexact_ui(mpz_t q, const mpz_t n, mp_limb_t d) {
  CHECK(mpz_div_ui_inner(q, n, d, 0) == 0);
}

/*
 * Left Shift
 */

void
mpz_lshift(mpz_t z, const mpz_t x, int bits) {
  int xn, zn;

  if (bits < 0) {
    mpz_rshift(z, x, -bits);
    return;
  }

  if (x->size == 0) {
    z->size = 0;
    return;
  }

  if (bits == 0) {
    mpz_set(z, x);
    return;
  }

  xn = MP_ABS(x->size);
  zn = xn + (bits + MP_LIMB_BITS - 1) / MP_LIMB_BITS;

  mpz_grow(z, zn);

  zn = mpv_lshift(z->limbs, x->limbs, xn, bits);

  z->size = x->size < 0 ? -zn : zn;
}

/*
 * Right Shift
 */

void
mpz_rshift(mpz_t z, const mpz_t x, int bits) {
  int xn, zn;

  if (bits < 0) {
    mpz_lshift(z, x, -bits);
    return;
  }

  if (x->size == 0) {
    z->size = 0;
    return;
  }

  if (bits == 0) {
    mpz_set(z, x);
    return;
  }

  xn = MP_ABS(x->size);
  zn = xn;

  mpz_grow(z, zn);

  zn = mpv_rshift(z->limbs, x->limbs, xn, bits);

  z->size = x->size < 0 ? -zn : zn;
}

/*
 * Bit Manipulation
 */

mp_limb_t
mpz_get_bit(const mpz_t x, int pos) {
  return mpn_get_bit(x->limbs, MP_ABS(x->size), pos);
}

mp_limb_t
mpz_get_bits(const mpz_t x, int pos, int width) {
  return mpn_get_bits(x->limbs, MP_ABS(x->size), pos, width);
}

void
mpz_set_bit(mpz_t x, int pos) {
  int index = pos / MP_LIMB_BITS;
  int xn = MP_ABS(x->size);

  if (xn < index + 1) {
    mpz_grow(x, index + 1);

    while (xn < index + 1)
      x->limbs[xn++] = 0;

    x->size = x->size < 0 ? -xn : xn;
  }

  x->limbs[index] |= MP_LIMB_C(1) << (pos % MP_LIMB_BITS);
}

void
mpz_clr_bit(mpz_t x, int pos) {
  int index = pos / MP_LIMB_BITS;

  if (index < MP_ABS(x->size))
    x->limbs[index] &= ~(MP_LIMB_C(1) << (pos % MP_LIMB_BITS));
}

/*
 * Negation
 */

void
mpz_abs(mpz_t z, const mpz_t x) {
  mpz_set(z, x);
  z->size = MP_ABS(z->size);
}

void
mpz_neg(mpz_t z, const mpz_t x) {
  mpz_set(z, x);
  z->size = -z->size;
}

/*
 * Number Theoretic Functions
 */

void
mpz_gcd(mpz_t z, const mpz_t x, const mpz_t y) {
  /* Binary GCD algorithm.
   *
   * [KNUTH] Algorithm B, Page 338, Section 4.5.2.
   */
  int i, j, shift, cmp;
  mpz_t a, b;

  if (x->size == 0) {
    mpz_abs(z, y);
    return;
  }

  if (y->size == 0) {
    mpz_abs(z, x);
    return;
  }

  mpz_init(a);
  mpz_init(b);

  mpz_abs(a, x);
  mpz_abs(b, y);

  /* Remove common factor of two. */
  i = mpz_ctz(a);
  j = mpz_ctz(b);

  shift = MP_MIN(i, j);

  if (shift > 0) {
    mpz_rshift(a, a, shift);
    mpz_rshift(b, b, shift);
  }

  for (;;) {
    i = mpz_ctz(a);
    j = mpz_ctz(b);

    if (i > 0)
      mpz_rshift(a, a, i);

    if (j > 0)
      mpz_rshift(b, b, j);

    cmp = mpz_cmpabs(a, b);

    if (cmp < 0) {
      /* Maintain a >= b. */
      mpz_swap(a, b);
    } else if (cmp == 0 || mpz_cmpabs_ui(b, 1) == 0) {
      /* Break if a == b. */
      /* Break if b == 1 to avoid repeated subtraction. */
      break;
    }

    mpz_sub(a, a, b);
  }

  mpz_lshift(z, b, shift);

  mpz_clear(a);
  mpz_clear(b);
}

void
mpz_lcm(mpz_t z, const mpz_t x, const mpz_t y) {
  mpz_t g, l;

  if (x->size == 0 || y->size == 0) {
    z->size = 0;
    return;
  }

  mpz_init(g);
  mpz_init(l);

  mpz_gcd(g, x, y);
  mpz_divexact(l, x, g);
  mpz_mul(z, l, y);
  mpz_abs(z, z);

  mpz_clear(g);
  mpz_clear(l);
}

void
mpz_gcdext(mpz_t g, mpz_t s, mpz_t t, const mpz_t x, const mpz_t y) {
  /* Euclid's algorithm for large numbers.
   *
   * [KNUTH] Algorithm L, Page 347, Section 4.5.2.
   */
  mpz_t u, v, A, B, C, D, up, vp;
  int i, j, shift;

  mpz_init(u);
  mpz_init(v);
  mpz_init(A);
  mpz_init(B);
  mpz_init(C);
  mpz_init(D);
  mpz_init(up);
  mpz_init(vp);

  if (x->size == 0) {
    if (g != NULL)
      mpz_abs(g, y);

    if (s != NULL)
      s->size = 0;

    if (t != NULL) {
      mpz_set_ui(t, y->size != 0);

      if (y->size < 0)
        mpz_neg(t, t);
    }

    return;
  }

  if (y->size == 0) {
    if (g != NULL)
      mpz_abs(g, x);

    if (s != NULL) {
      mpz_set_ui(s, x->size != 0);

      if (x->size < 0)
        mpz_neg(s, s);
    }

    if (t != NULL)
      t->size = 0;

    return;
  }

  mpz_abs(u, x);
  mpz_abs(v, y);

  /* A * u + B * v = u */
  mpz_set_ui(A, 1);
  mpz_set_ui(B, 0);

  /* C * u + D * v = v */
  mpz_set_ui(C, 0);
  mpz_set_ui(D, 1);

  /* Remove common factor of two. */
  i = mpz_ctz(u);
  j = mpz_ctz(v);

  shift = MP_MIN(i, j);

  if (shift > 0) {
    mpz_rshift(u, u, shift);
    mpz_rshift(v, v, shift);
  }

  mpz_set(up, u);
  mpz_set(vp, v);

  while (u->size != 0) {
    i = mpz_ctz(u);
    j = mpz_ctz(v);

    if (i > 0)
      mpz_rshift(u, u, i);

    if (j > 0)
      mpz_rshift(v, v, j);

    while (i--) {
      if (mpz_odd_p(A) || mpz_odd_p(B)) {
        mpz_add(A, A, vp);
        mpz_sub(B, B, up);
      }

      mpz_rshift(A, A, 1);
      mpz_rshift(B, B, 1);
    }

    while (j--) {
      if (mpz_odd_p(C) || mpz_odd_p(D)) {
        mpz_add(C, C, vp);
        mpz_sub(D, D, up);
      }

      mpz_rshift(C, C, 1);
      mpz_rshift(D, D, 1);
    }

    if (mpz_cmp(u, v) >= 0) {
      mpz_sub(u, u, v);
      mpz_sub(A, A, C);
      mpz_sub(B, B, D);
    } else {
      mpz_sub(v, v, u);
      mpz_sub(C, C, A);
      mpz_sub(D, D, B);
    }
  }

  if (x->size < 0)
    mpz_neg(C, C);

  if (y->size < 0)
    mpz_neg(D, D);

  if (g != NULL)
    mpz_lshift(g, v, shift);

  if (s != NULL)
    mpz_set(s, C);

  if (t != NULL)
    mpz_set(t, D);

  mpz_clear(u);
  mpz_clear(v);
  mpz_clear(A);
  mpz_clear(B);
  mpz_clear(C);
  mpz_clear(D);
  mpz_clear(up);
  mpz_clear(vp);
}

static int
mpz_invert_inner(mpz_t z, const mpz_t x, const mpz_t y) {
  int xn = MP_ABS(x->size);
  int yn = MP_ABS(y->size);
  int itch = MPN_INVERT_ITCH(yn);
  mp_limb_t *scratch = mp_alloc_vla(itch);
  int ret;

  mpz_grow(z, yn);

  ret = mpn_invert(z->limbs, x->limbs, xn,
                             y->limbs, yn,
                             scratch);

  z->size = mpn_strip(z->limbs, yn);

  mp_free_vla(scratch, itch);

  return ret;
}

int
mpz_invert(mpz_t z, const mpz_t x, const mpz_t y) {
  mpz_t g, s;
  int ret;

  if (x->size == 0 || mpz_cmpabs_ui(y, 1) <= 0)
    return 0;

  if (mpz_odd_p(y)) {
    if (mpz_sgn(x) < 0 || mpz_cmpabs(x, y) >= 0) {
      mpz_init(g);
      mpz_mod(g, x, y);

      ret = mpz_invert_inner(z, g, y);

      mpz_clear(g);
    } else {
      ret = mpz_invert_inner(z, x, y);
    }
  } else {
    mpz_init(g);
    mpz_init(s);

    mpz_gcdext(g, s, NULL, x, y);

    if (mpz_cmp_ui(g, 1) == 0) {
      mpz_mod(z, s, y);
      ret = 1;
    } else {
      ret = 0;
    }

    mpz_clear(g);
    mpz_clear(s);
  }

  return ret;
}

static int
mpz_jacobi_inner(const mpz_t x, const mpz_t y) {
  int xn = MP_ABS(x->size);
  int yn = MP_ABS(y->size);
  int itch = MPN_JACOBI_ITCH(yn);
  mp_limb_t *scratch = mp_alloc_vla(itch);
  int j;

  j = mpn_jacobi(x->limbs, xn, y->limbs, yn, scratch);

  mp_free_vla(scratch, itch);

  return j;
}

int
mpz_jacobi(const mpz_t x, const mpz_t y) {
  mpz_t t;
  int j;

  if (mpz_sgn(x) < 0 || mpz_cmpabs(x, y) >= 0) {
    mpz_init(t);
    mpz_mod(t, x, y);

    j = mpz_jacobi_inner(t, y);

    mpz_clear(t);
  } else {
    j = mpz_jacobi_inner(x, y);
  }

  return j;
}

static void
mpz_powm_inner(mpz_t z, const mpz_t x, const mpz_t y, const mpz_t m) {
  int xn = MP_ABS(x->size);
  int yn = MP_ABS(y->size);
  int mn = MP_ABS(m->size);
  int itch = MPN_POWM_ITCH(yn, mn);
  mp_limb_t *scratch = mp_alloc_limbs(itch);

  mpz_grow(z, mn);

  mpn_powm(z->limbs, x->limbs, xn,
                     y->limbs, yn,
                     m->limbs, mn,
                     scratch);

  z->size = mpn_strip(z->limbs, mn);

  mp_free_limbs(scratch);
}

void
mpz_powm(mpz_t z, const mpz_t x, const mpz_t y, const mpz_t m) {
  mpz_t t;

  if (mpz_sgn(x) < 0 || mpz_cmpabs(x, m) >= 0 || mpz_sgn(y) < 0) {
    mpz_init(t);

    if (mpz_sgn(y) < 0) {
      if (!mpz_invert(t, x, m))
        torsion_abort(); /* LCOV_EXCL_LINE */
    } else {
      mpz_mod(t, x, m);
    }

    mpz_powm_inner(z, t, y, m);
    mpz_clear(t);
  } else {
    mpz_powm_inner(z, x, y, m);
  }
}

static void
mpz_powm_sec_inner(mpz_t z, const mpz_t x, const mpz_t y, const mpz_t m) {
  int xn = MP_ABS(x->size);
  int yn = MP_ABS(y->size);
  int mn = MP_ABS(m->size);
  int itch = MPN_SEC_POWM_ITCH(mn);
  mp_limb_t *scratch = mp_alloc_limbs(itch);

  mpz_grow(z, mn);

  if (y->size < 0 || m->size == 0 || (m->limbs[0] & 1) == 0)
    torsion_abort(); /* LCOV_EXCL_LINE */

  mpn_sec_powm(z->limbs, x->limbs, xn,
                         y->limbs, yn,
                         m->limbs, mn,
                         scratch);

  z->size = mpn_strip(z->limbs, mn);

  mp_free_limbs(scratch);
}

void
mpz_powm_sec(mpz_t z, const mpz_t x, const mpz_t y, const mpz_t m) {
  mpz_t t;

  if (mpz_sgn(x) < 0 || mpz_cmpabs(x, m) >= 0) {
    mpz_init(t);
    mpz_mod(t, x, m);
    mpz_powm_sec_inner(z, t, y, m);
    mpz_clear(t);
  } else {
    mpz_powm_sec_inner(z, x, y, m);
  }
}

/*
 * Primality Testing (logic from golang)
 */

int
mpz_is_prime_mr(const mpz_t n, int reps, int force2, mp_rng_f *rng, void *arg) {
  /* Miller-Rabin Primality Test.
   *
   * [HANDBOOK] Algorithm 4.24, Page 139, Section 4.2.3.
   */
  mpz_t nm1, nm3, q, x, y;
  int ret = 0;
  int i, j, k;

  /* if n < 7 */
  if (mpz_cmp_ui(n, 7) < 0) {
    /* n == 2 or n == 3 or n == 5 */
    return mpz_cmp_ui(n, 2) == 0
        || mpz_cmp_ui(n, 3) == 0
        || mpz_cmp_ui(n, 5) == 0;
  }

  /* if n mod 2 == 0 */
  if (mpz_even_p(n))
    return 0;

  mpz_init(nm1);
  mpz_init(nm3);
  mpz_init(q);
  mpz_init(x);
  mpz_init(y);

  /* nm1 = n - 1 */
  mpz_sub_ui(nm1, n, 1);

  /* nm3 = nm1 - 2 */
  mpz_sub_ui(nm3, nm1, 2);

  /* k = nm1 factors of 2 */
  k = mpz_ctz(nm1);

  /* q = nm1 >> k */
  mpz_rshift(q, nm1, k);

  for (i = 0; i < reps; i++) {
    if (i == reps - 1 && force2) {
      /* x = 2 */
      mpz_set_ui(x, 2);
    } else {
      /* x = random integer in [2,n-1] */
      mpz_random_int(x, nm3, rng, arg);
      mpz_add_ui(x, x, 2);
    }

    /* y = x^q mod n */
    mpz_powm(y, x, q, n);

    /* if y == 1 or y == -1 mod n */
    if (mpz_cmp_ui(y, 1) == 0 || mpz_cmp(y, nm1) == 0)
      continue;

    for (j = 1; j < k; j++) {
      /* y = y^2 mod n */
      mpz_sqr(y, y);
      mpz_mod(y, y, n);

      /* if y == -1 mod n */
      if (mpz_cmp(y, nm1) == 0)
        goto next;

      /* if y == 1 mod n */
      if (mpz_cmp_ui(y, 1) == 0)
        goto fail;
    }

    goto fail;
next:
    ;
  }

  ret = 1;
fail:
  mpz_clear(nm1);
  mpz_clear(nm3);
  mpz_clear(q);
  mpz_clear(x);
  mpz_clear(y);
  return ret;
}

int
mpz_is_prime_lucas(const mpz_t n, mp_limb_t limit) {
  /* Lucas Primality Test.
   *
   * [LUCAS] Page 1401, Section 5.
   */
  mpz_t d, s, nm2, vk, vk1, t1, t2, t3;
  int i, j, r, t;
  int ret = 0;
  mp_limb_t p;

  mpz_init(d);
  mpz_init(s);
  mpz_init(nm2);
  mpz_init(vk);
  mpz_init(vk1);
  mpz_init(t1);
  mpz_init(t2);
  mpz_init(t3);

  /* if n <= 1 */
  if (mpz_cmp_ui(n, 1) <= 0)
    goto fail;

  /* if n mod 2 == 0 */
  if (mpz_even_p(n)) {
    /* if n == 2 */
    if (mpz_cmp_ui(n, 2) == 0)
      goto succeed;
    goto fail;
  }

  /* p = 3 */
  p = 3;

  /* d = 1 */
  mpz_set_ui(d, 1);

  for (;;) {
    if (p > 10000) {
      /* Thought to be impossible. */
      goto fail;
    }

    if (limit != 0 && p > limit) {
      /* Enforce a limit to prevent DoS'ing. */
      goto fail;
    }

    /* d = p * p - 4 */
    mpz_set_ui(d, p * p - 4);

    j = mpz_jacobi(d, n);

    /* if d is not square mod n */
    if (j == -1)
      break;

    /* if d == 0 mod n */
    if (j == 0) {
      /* if n == p + 2 */
      if (mpz_cmp_ui(n, p + 2) == 0)
        goto succeed;
      goto fail;
    }

    if (p == 40) {
      /* if floor(n^(1 / 2))^2 == n */
      mpz_set_bit(t2, mpz_bitlen(n) / 2 + 1);

      do {
        mpz_swap(t1, t2);
        mpz_quo(t2, n, t1);
        mpz_add(t2, t2, t1);
        mpz_rshift(t2, t2, 1);
      } while (mpz_cmpabs(t2, t1) < 0);

      mpz_sqr(t2, t1);

      if (mpz_cmp(t2, n) == 0)
        goto fail;
    }

    p += 1;
  }

  /* s = n + 1 */
  mpz_add_ui(s, n, 1);

  /* r = s factors of 2 */
  r = mpz_ctz(s);

  /* s >>= r */
  mpz_rshift(s, s, r);

  /* nm2 = n - 2 */
  mpz_sub_ui(nm2, n, 2);

  /* vk = 2 */
  mpz_set_ui(vk, 2);

  /* vk1 = p */
  mpz_set_ui(vk1, p);

  for (i = mpz_bitlen(s); i >= 0; i--) {
    /* if floor(s / 2^i) mod 2 == 1 */
    if (mpz_get_bit(s, i)) {
      /* vk = (vk * vk1 + n - p) mod n */
      /* vk1 = (vk1^2 + nm2) mod n */
      mpz_mul(t1, vk, vk1);
      mpz_add(t1, t1, n);
      mpz_sub_ui(t1, t1, p);
      mpz_mod(vk, t1, n);
      mpz_sqr(t1, vk1);
      mpz_add(t1, t1, nm2);
      mpz_mod(vk1, t1, n);
    } else {
      /* vk1 = (vk * vk1 + n - p) mod n */
      /* vk = (vk^2 + nm2) mod n */
      mpz_mul(t1, vk, vk1);
      mpz_add(t1, t1, n);
      mpz_sub_ui(t1, t1, p);
      mpz_mod(vk1, t1, n);
      mpz_sqr(t1, vk);
      mpz_add(t1, t1, nm2);
      mpz_mod(vk, t1, n);
    }
  }

  /* if vk == 2 or vk == nm2 */
  if (mpz_cmp_ui(vk, 2) == 0 || mpz_cmp(vk, nm2) == 0) {
    /* t3 = abs(vk * p - vk1 * 2) mod n */
    mpz_mul_ui(t1, vk, p);
    mpz_lshift(t2, vk1, 1);

    if (mpz_cmp(t1, t2) < 0)
      mpz_swap(t1, t2);

    mpz_sub(t1, t1, t2);
    mpz_mod(t3, t1, n);

    /* if t3 == 0 */
    if (mpz_sgn(t3) == 0)
      goto succeed;
  }

  for (t = 0; t < r - 1; t++) {
    /* if vk == 0 */
    if (mpz_sgn(vk) == 0)
      goto succeed;

    /* if vk == 2 */
    if (mpz_cmp_ui(vk, 2) == 0)
      goto fail;

    /* vk = (vk^2 - 2) mod n */
    mpz_sqr(t1, vk);
    mpz_sub_ui(t1, t1, 2);
    mpz_mod(vk, t1, n);
  }

  goto fail;
succeed:
  ret = 1;
fail:
  mpz_clear(d);
  mpz_clear(s);
  mpz_clear(nm2);
  mpz_clear(vk);
  mpz_clear(vk1);
  mpz_clear(t1);
  mpz_clear(t2);
  mpz_clear(t3);
  return ret;
}

int
mpz_is_prime(const mpz_t n, int rounds, mp_rng_f *rng, void *arg) {
  /* Baillie-PSW Primality Test.
   *
   * [BPSW] "Bibliography".
   */
  /* 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 37 */
  static const mp_limb_t primes_a = MP_LIMB_C(4127218095);
  /* 29 * 31 * 41 * 43 * 47 * 53 */
  static const mp_limb_t primes_b = MP_LIMB_C(3948078067);
  /* First 18 primes in a mask (2-61). */
  static const uint64_t prime_mask = UINT64_C(0x28208a20a08a28ac);
  mp_limb_t ra, rb;
#if MP_LIMB_BITS == 64
  mp_limb_t r;
#endif

  if (mpz_sgn(n) <= 0)
    return 0;

  if (mpz_cmp_ui(n, 64) < 0)
    return (prime_mask >> mpz_get_ui(n)) & 1;

  if (mpz_even_p(n))
    return 0;

#if MP_LIMB_BITS == 32
  ra = mpz_rem_ui(n, primes_a);
  rb = mpz_rem_ui(n, primes_b);
#else
  r = mpz_rem_ui(n, primes_a * primes_b);
  ra = r % primes_a;
  rb = r % primes_b;
#endif

  if (ra % 3 == 0
      || ra % 5 == 0
      || ra % 7 == 0
      || ra % 11 == 0
      || ra % 13 == 0
      || ra % 17 == 0
      || ra % 19 == 0
      || ra % 23 == 0
      || ra % 37 == 0
      || rb % 29 == 0
      || rb % 31 == 0
      || rb % 41 == 0
      || rb % 43 == 0
      || rb % 47 == 0
      || rb % 53 == 0) {
    return 0;
  }

  if (!mpz_is_prime_mr(n, rounds + 1, 1, rng, arg))
    return 0;

  if (!mpz_is_prime_lucas(n, 0))
    return 0;

  return 1;
}

void
mpz_random_prime(mpz_t z, int bits, mp_rng_f *rng, void *arg) {
  static const uint64_t primes[15] = { 3, 5, 7, 11, 13, 17, 19, 23,
                                       29, 31, 37, 41, 43, 47, 53 };
  static const uint64_t product = UINT64_C(16294579238595022365);
  uint64_t mod, delta, m, p;
  size_t i;

  CHECK(bits > 1);

  for (;;) {
    mpz_random_bits(z, bits, rng, arg);

    mpz_set_bit(z, bits - 1);
    mpz_set_bit(z, bits - 2);
    mpz_set_bit(z, 0);

#if MP_LIMB_BITS == 32
    mod = mpn_mod_2(z->limbs, z->size, product);
#else
    mod = mpz_rem_ui(z, product);
#endif

    for (delta = 0; delta < (UINT64_C(1) << 20); delta += 2) {
      m = mod + delta;

      for (i = 0; i < ARRAY_SIZE(primes); i++) {
        p = primes[i];

        if ((m % p) == 0 && (bits > 6 || m != p))
          goto next;
      }

      mpz_add_ui(z, z, (mp_limb_t)delta);

      break;
next:
      ;
    }

    if (mpz_bitlen(z) != bits)
      continue;

    if (!mpz_is_prime(z, 20, rng, arg))
      continue;

    break;
  }
}

/*
 * Helpers
 */

int
mpz_odd_p(const mpz_t x) {
  if (x->size == 0)
    return 0;

  return x->limbs[0] & 1;
}

int
mpz_even_p(const mpz_t x) {
  return !mpz_odd_p(x);
}

int
mpz_ctz(const mpz_t x) {
  return mpn_ctz(x->limbs, MP_ABS(x->size));
}

int
mpz_bitlen(const mpz_t x) {
  return mpn_bitlen(x->limbs, MP_ABS(x->size));
}

size_t
mpz_bytelen(const mpz_t x) {
  return (mpz_bitlen(x) + 7) / 8;
}

void
mpz_swap(mpz_t x, mpz_t y) {
  mp_limb_t *limbs = x->limbs;
  int alloc = x->alloc;
  int size = x->size;

  x->limbs = y->limbs;
  x->alloc = y->alloc;
  x->size = y->size;

  y->limbs = limbs;
  y->alloc = alloc;
  y->size = size;
}

/*
 * Import
 */

void
mpz_import(mpz_t z, const unsigned char *raw, size_t size, int endian) {
  int zn = (mp_cast_size(size) + MP_LIMB_BYTES - 1) / MP_LIMB_BYTES;

  if (zn == 0) {
    z->size = 0;
    return;
  }

  mpz_grow(z, zn);

  mpn_import(z->limbs, zn, raw, size, endian);

  z->size = mpn_strip(z->limbs, zn);
}

/*
 * Export
 */

void
mpz_export(unsigned char *raw, const mpz_t x, size_t size, int endian) {
  CHECK(size >= mpz_bytelen(x));
  mpn_export(raw, size, x->limbs, MP_ABS(x->size), endian);
}

/*
 * RNG
 */

void
mpz_random_bits(mpz_t z, int bits, mp_rng_f *rng, void *arg) {
  int zn = (bits + MP_LIMB_BITS - 1) / MP_LIMB_BITS;
  int lo = bits % MP_LIMB_BITS;

  mpz_grow(z, zn);

  rng(z->limbs, zn * sizeof(mp_limb_t), arg);

  if (lo != 0)
    z->limbs[zn - 1] &= (MP_LIMB_C(1) << lo) - 1;

  z->size = mpn_strip(z->limbs, zn);

  ASSERT(mpz_bitlen(z) <= bits);
}

void
mpz_random_int(mpz_t z, const mpz_t max, mp_rng_f *rng, void *arg) {
  int bits = mpz_bitlen(max);

  if (bits > 0) {
    do {
      mpz_random_bits(z, bits, rng, arg);
    } while (mpz_cmpabs(z, max) >= 0);

    if (mpz_sgn(max) < 0)
      mpz_neg(z, z);
  } else {
    z->size = 0;
  }
}
