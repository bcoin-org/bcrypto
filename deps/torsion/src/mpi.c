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
 *
 *   [ARITH] Modern Computer Arithmetic
 *     Richard P. Brent, Paul Zimmermann
 *     https://members.loria.fr/PZimmermann/mca/pub226.html
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

#if defined(__GNUC__) || __has_builtin(__builtin_alloca)
#  define mp_alloca __builtin_alloca
#elif defined(_MSC_VER)
#  include <malloc.h>
#  define mp_alloca _alloca
#endif

#if defined(mp_alloca)
/* Max stack allocation size for alloca: */
/* 1536 bytes (three 4096 bit RSA moduli). */
#  define mp_alloca_max ((3 * 4096) / MP_LIMB_BITS + 1)
#  define mp_alloca_limbs(n) ((mp_limb_t *)mp_alloca((n) * sizeof(mp_limb_t)))
#  define mp_alloc_vla(n) \
     ((n) > mp_alloca_max ? mp_alloc_limbs(n) : mp_alloca_limbs(n))
#  define mp_free_vla(p, n) \
     do { if ((n) > mp_alloca_max) mp_free_limbs(p); } while (0)
#  define mp_alloc_str(n) ((char *)((n) > 1024 ? malloc(n) : mp_alloca(n)))
#  define mp_free_str(p, n) do { if ((n) > 1024) free(p); } while (0)
#else
#  define mp_alloca_max 0
#  define mp_alloc_vla(n) mp_alloc_limbs(n)
#  define mp_free_vla(p, n) mp_free_limbs(p)
#  define mp_alloc_str(n) ((char *)malloc(n))
#  define mp_free_str(p, n) free(p)
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

/* [z, c] = z + x * y + c */
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
  mp_wide_t _w = (z) + (mp_wide_t)(x) * (y) + (c); \
  (c) = _w >> MP_LIMB_BITS;                        \
  (z) = _w;                                        \
} while (0)

#define mp_submul_1(z, c, x, y) do {               \
  mp_wide_t _w = (z) - (mp_wide_t)(x) * (y) - (c); \
  (c) = -(_w >> MP_LIMB_BITS);                     \
  (z) = _w;                                        \
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
mpv_set_1(mp_limb_t *zp, mp_limb_t x);

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
mpv_sqr_1(mp_limb_t *zp, mp_limb_t x);

static TORSION_INLINE int
mpv_sqr(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t *scratch);

static TORSION_INLINE int
mpv_lshift(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits);

static TORSION_INLINE int
mpv_rshift(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits);

/*
 * Internal Helpers
 */

static int
mpz_ctz_common(const mpz_t x, const mpz_t y);

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
 * Helpers
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
mp_mul_gt_2(mp_limb_t u, mp_limb_t v, mp_limb_t y1, mp_limb_t y0) {
  mp_limb_t x1, x0;

  mp_mul(x1, x0, u, v);

  return x1 > y1 || (x1 == y1 && x0 > y0);
}

static TORSION_INLINE int
mp_cast_size(size_t n) {
  CHECK(n <= (size_t)INT_MAX);
  return n;
}

static TORSION_INLINE mp_limb_t
mp_long_abs(mp_long_t x) {
  if (x == MP_LONG_MIN)
    return MP_LIMB_HI;

  return MP_ABS(x);
}

static TORSION_INLINE mp_long_t
mp_limb_cast(mp_limb_t x, int sign) {
  if (sign) {
    if (x == MP_LIMB_HI)
      return MP_LONG_MIN;

    return -((mp_long_t)(x & (MP_LIMB_HI - 1)));
  }

  return x & (MP_LIMB_HI - 1);
}

static TORSION_INLINE int
mp_isspace(int ch) {
  switch (ch) {
    case '\t':
    case '\n':
    case '\r':
    case ' ':
      return 1;
  }
  return 0;
}

static int
mp_str_limbs(const char *str, int base) {
  mp_limb_t max, limb_pow;
  int limb_len;
  int len = 0;

  while (*str)
    len += !mp_isspace(*str++);

  if (len == 0)
    len = 1;

  if (base < 2)
    base = 2;
  else if (base > 36)
    base = 36;

  if ((base & (base - 1)) == 0)
    return (len * mp_bitlen(base - 1) + MP_LIMB_BITS - 1) / MP_LIMB_BITS;

  max = MP_LIMB_MAX / base;
  limb_pow = base;
  limb_len = 1;

  while (limb_pow <= max) {
    limb_pow *= base;
    limb_len += 1;
  }

  return (len + limb_len - 1) / limb_len;
}

/*
 * MPN Interface
 */

/*
 * Initialization
 */

void
mpn_zero(mp_limb_t *zp, int zn) {
  int i;

  for (i = 0; i < zn; i++)
    zp[i] = 0;
}

/*
 * Uninitialization
 */

void
torsion_cleanse(void *, size_t);

void
mpn_cleanse(mp_limb_t *zp, int zn) {
  torsion_cleanse(zp, zn * sizeof(mp_limb_t));
}

/*
 * Assignment
 */

void
mpn_set_1(mp_limb_t *zp, int zn, mp_limb_t x) {
  ASSERT(zn > 0);

  zp[0] = x;

  mpn_zero(zp + 1, zn - 1);
}

void
mpn_copyi(mp_limb_t *zp, const mp_limb_t *xp, int xn) {
  int i;

  for (i = 0; i < xn; i++)
    zp[i] = xp[i];
}

void
mpn_copyd(mp_limb_t *zp, const mp_limb_t *xp, int xn) {
  int i;

  for (i = xn - 1; i >= 0; i--)
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
    /* [z, c] = z + x * y + c */
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
  int s = bits / MP_LIMB_BITS;
  int r = bits % MP_LIMB_BITS;
  mp_limb_t *tp = scratch;
  int tn = n * 2;
  int zn = tn - s;
  mp_limb_t b;

  /* Ensure L <= bits <= 2 * L. */
  ASSERT(s >= n && s <= n * 2);
  ASSERT(zn >= 0 && zn <= n);
  ASSERT(zn != 0);

  /* t = x * y */
  mpn_mul_n(tp, xp, yp, n);

  /* b = (t >> (bits - 1)) & 1 */
  b = mpn_getbit(tp, tn, bits - 1);

  /* z = t >> bits */
  if (r != 0)
    mpn_rshift(zp, tp + s, zn, r);
  else
    mpn_copyi(zp, tp + s, zn);

  mpn_zero(zp + zn, n - zn);

  /* z += b */
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
   * `shift + 1` limbs are required for scratch.
   *
   * Must have `shift - n + 1` limbs at mp.
   */
  mp_limb_t *xp = scratch;
  int xn = shift + 1;

  CHECK(n > 0);
  CHECK(shift >= n * 2);

  /* m = 2^(shift * L) / n */
  mpn_zero(xp, shift);

  xp[shift] = 1;

  mpn_div(xp, xp, xn, np, n);

  CHECK(mpn_strip(xp, xn - n + 1) == shift - n + 1);

  mpn_copyi(mp, xp, shift - n + 1);
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

#ifdef TORSION_VERIFY
  ASSERT(mpn_cmp(zp, np, n) < 0);
#endif
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

#ifdef TORSION_VERIFY
  ASSERT(mpn_cmp(zp, mp, n) < 0);
#endif
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
    mpn_copyi(zp, tp + n, n);
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
      mpn_copyi(den->vp, dp, dn);
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
  mp_limb_t qhat, rhat, prev, c;
  mp_limb_t *up = den->up;
  mp_limb_t m = den->inv;
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
    mpn_copyi(up, np, nn);
    up[nn] = 0;
  }

  for (j = nn - dn; j >= 0; j--) {
    /* Compute estimate qhat of qp[j]. */
    qhat = MP_LIMB_MAX;

    if (up[j + dn] != vp[dn - 1]) {
      mp_div_2by1(&qhat, &rhat, up[j + dn], up[j + dn - 1], vp[dn - 1], m);

      while (mp_mul_gt_2(qhat, vp[dn - 2], rhat, up[j + dn - 2])) {
        prev = rhat;
        qhat -= 1;
        rhat += vp[dn - 1];

        if (rhat < prev)
          break;
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
      mpn_copyi(rp, up, dn);
  }
}

static TORSION_INLINE void
mpn_mod_inner(mp_limb_t *rp, const mp_limb_t *np, int nn, mp_divisor_t *den) {
  nn = mpn_strip(np, nn);

  if (nn > den->size)
    mpn_divmod_inner(NULL, rp, np, nn, den);
  else
    mpn_copyi(rp, np, den->size);
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
 * Round Division
 */

void
mpn_divround(mp_limb_t *qp, const mp_limb_t *np, int nn,
                            const mp_limb_t *dp, int dn) {
  /* Computes q = (n + (d >> 1)) / d. */
  /* Requires nn - dn + 2 limbs at qp. */
  mp_limb_t *tp;
  int tn;

  if (dn <= 0 || nn < dn)
    torsion_abort(); /* LCOV_EXCL_LINE */

  tn = nn + 1;
  tp = mp_alloc_vla(tn);

  mpn_rshift(tp, dp, dn, 1);

  tp[nn] = mpn_add(tp, np, nn, tp, dn);

  mpn_div(qp, tp, tn, dp, dn);

  mp_free_vla(tp, tn);
}

/*
 * AND
 */

void
mpn_and_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  int i;

  for (i = 0; i < n; i++)
    zp[i] = xp[i] & yp[i];
}

/*
 * OR
 */

void
mpn_ior_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  int i;

  for (i = 0; i < n; i++)
    zp[i] = xp[i] | yp[i];
}

static void
mpn_ior(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                       const mp_limb_t *yp, int yn) {
  CHECK(xn >= yn);

  mpn_ior_n(zp, xp, yp, yn);
  mpn_copyi(zp + yn, xp + yn, xn - yn);
}

/*
 * XOR
 */

void
mpn_xor_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  int i;

  for (i = 0; i < n; i++)
    zp[i] = xp[i] ^ yp[i];
}

static void
mpn_xor(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                       const mp_limb_t *yp, int yn) {
  CHECK(xn >= yn);

  mpn_xor_n(zp, xp, yp, yn);
  mpn_copyi(zp + yn, xp + yn, xn - yn);
}

/*
 * AND+NOT
 */

void
mpn_andn_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  int i;

  for (i = 0; i < n; i++)
    zp[i] = xp[i] & ~yp[i];
}

static void
mpn_andn(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                        const mp_limb_t *yp, int yn) {
  if (xn >= yn) {
    mpn_andn_n(zp, xp, yp, yn);
    mpn_copyi(zp + yn, xp + yn, xn - yn);
  } else {
    mpn_andn_n(zp, xp, yp, xn);
  }
}

/*
 * OR+NOT
 */

void
mpn_iorn_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  int i;

  for (i = 0; i < n; i++)
    zp[i] = xp[i] | ~yp[i];
}

/*
 * NOT+AND
 */

void
mpn_nand_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  int i;

  for (i = 0; i < n; i++)
    zp[i] = ~(xp[i] & yp[i]);
}

/*
 * NOT+OR
 */

void
mpn_nior_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  int i;

  for (i = 0; i < n; i++)
    zp[i] = ~(xp[i] | yp[i]);
}

/*
 * NOT+XOR
 */

void
mpn_nxor_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n) {
  int i;

  for (i = 0; i < n; i++)
    zp[i] = ~(xp[i] ^ yp[i]);
}

/*
 * NOT
 */

void
mpn_com(mp_limb_t *zp, const mp_limb_t *xp, int xn) {
  int i;

  for (i = 0; i < xn; i++)
    zp[i] = ~xp[i];
}

/*
 * Left Shift
 */

mp_limb_t
mpn_lshift(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits) {
  mp_limb_t c;
  int i;

  ASSERT(xn > 0);
  ASSERT(bits > 0 && bits < MP_LIMB_BITS);

  c = xp[xn - 1] >> (MP_LIMB_BITS - bits);

  for (i = xn - 1; i >= 1; i--)
    zp[i] = (xp[i] << bits) | (xp[i - 1] >> (MP_LIMB_BITS - bits));

  zp[i] = xp[i] << bits;

  return c;
}

/*
 * Right Shift
 */

mp_limb_t
mpn_rshift(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits) {
  mp_limb_t c;
  int i;

  ASSERT(xn > 0);
  ASSERT(bits > 0 && bits < MP_LIMB_BITS);

  c = xp[0] << (MP_LIMB_BITS - bits);

  for (i = 0; i < xn - 1; i++)
    zp[i] = (xp[i + 1] << (MP_LIMB_BITS - bits)) | (xp[i] >> bits);

  zp[i] = xp[i] >> bits;

  return c >> (MP_LIMB_BITS - bits);
}

/*
 * Bit Manipulation
 */

mp_limb_t
mpn_getbit(const mp_limb_t *xp, int xn, int pos) {
  int index = pos / MP_LIMB_BITS;

  if (index >= xn)
    return 0;

  return (xp[index] >> (pos % MP_LIMB_BITS)) & 1;
}

mp_limb_t
mpn_getbits(const mp_limb_t *xp, int xn, int pos, int width) {
  int index = pos / MP_LIMB_BITS;
  mp_limb_t bits, next;
  int shift, more;

  ASSERT(width < MP_LIMB_BITS);

  if (index >= xn)
    return 0;

  shift = pos % MP_LIMB_BITS;
  bits = (xp[index] >> shift) & MP_MASK(width);

  if (shift + width > MP_LIMB_BITS && index + 1 < xn) {
    more = shift + width - MP_LIMB_BITS;
    next = xp[index + 1] & MP_MASK(more);

    bits |= next << (MP_LIMB_BITS - shift);
  }

  return bits;
}

void
mpn_setbit(mp_limb_t *zp, int pos) {
  zp[pos / MP_LIMB_BITS] |= MP_LIMB_C(1) << (pos % MP_LIMB_BITS);
}

void
mpn_clrbit(mp_limb_t *zp, int pos) {
  zp[pos / MP_LIMB_BITS] &= ~(MP_LIMB_C(1) << (pos % MP_LIMB_BITS));
}

void
mpn_mask(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits) {
  int zn = bits / MP_LIMB_BITS;
  int lo = bits % MP_LIMB_BITS;

  if (zn >= xn) {
    mpn_copyi(zp, xp, xn);
    return;
  }

  mpn_copyi(zp, xp, zn);

  if (lo != 0) {
    zp[zn] = xp[zn] & MP_MASK(lo);
    zn += 1;
  }

  if (xn > zn)
    mpn_zero(zp + zn, xn - zn);
}

/*
 * Negation
 */

mp_limb_t
mpn_neg(mp_limb_t *zp, const mp_limb_t *xp, int xn) {
  mp_limb_t c = 0;
  int i;

  for (i = 0; i < xn; i++) {
    /* [z, c] = 0 - x - c */
    mp_sub_1(zp[i], c, MP_LIMB_C(0), xp[i]);
  }

  return c;
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

  mpn_copyi(zp, vp, vn);
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

  mpn_copyi(ap, xp, xn);
  mpn_zero(ap + xn, mn - xn);

  mpn_divmod_init(&den, sn, mp, mn);

  len = mpn_bitlen(yp, yn);

  ASSERT(len > 0);

  if (yn > 2 && len >= MP_SLIDE_WIDTH) {
    mpn_sqr(sp, ap, mn, tp);
    mpn_mod_inner(rp, sp, sn, &den);

#define WND(i) (&wp[(i) * mn])

    mpn_copyi(WND(0), ap, mn);

    for (i = 1; i < MP_SLIDE_SIZE; i++) {
      mpn_mul_n(sp, WND(i - 1), rp, mn);
      mpn_mod_inner(WND(i), sp, sn, &den);
    }

    i = len;

    while (i >= MP_SLIDE_WIDTH) {
      width = MP_SLIDE_WIDTH;
      bits = mpn_getbits(yp, yn, i - width, width);

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
        mpn_copyi(rp, WND(bits >> 1), mn);
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
    mpn_copyi(rp, ap, mn);

    i = len - 1;
  }

  for (i -= 1; i >= 0; i--) {
    mpn_sqr(sp, rp, mn, tp);
    mpn_mod_inner(rp, sp, sn, &den);

    if (mpn_getbit(yp, yn, i)) {
      mpn_mul_n(sp, rp, ap, mn);
      mpn_mod_inner(rp, sp, sn, &den);
    }
  }

  if (mpn_cmp(rp, mp, mn) >= 0)
    mpn_divmod_inner(NULL, zp, rp, mn, &den);
  else
    mpn_copyi(zp, rp, mn);

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

  mpn_copyi(ap, xp, xn);
  mpn_zero(ap + xn, mn - xn);

  mpn_mont(&k, rr, mp, mn, tp);

  mpn_montmul_var(ap, ap, rr, mp, mn, k, tp);

  if (yn > 2 && len >= MP_SLIDE_WIDTH) {
    mpn_montmul_var(rp, ap, ap, mp, mn, k, tp);

#define WND(i) (&wp[(i) * mn])

    mpn_copyi(WND(0), ap, mn);

    for (i = 1; i < MP_SLIDE_SIZE; i++)
      mpn_montmul_var(WND(i), WND(i - 1), rp, mp, mn, k, tp);

    i = len;

    while (i >= MP_SLIDE_WIDTH) {
      width = MP_SLIDE_WIDTH;
      bits = mpn_getbits(yp, yn, i - width, width);

      if (bits < MP_SLIDE_SIZE) {
        mpn_montmul_var(rp, rp, rp, mp, mn, k, tp);
        i -= 1;
        continue;
      }

      shift = mp_ctz(bits);
      width -= shift;
      bits >>= shift;

      if (i == len) {
        mpn_copyi(rp, WND(bits >> 1), mn);
      } else {
        for (j = 0; j < width; j++)
          mpn_montmul_var(rp, rp, rp, mp, mn, k, tp);

        mpn_montmul_var(rp, rp, WND(bits >> 1), mp, mn, k, tp);
      }

#undef WND

      i -= width;
    }
  } else {
    mpn_copyi(rp, ap, mn);

    i = len - 1;
  }

  for (i -= 1; i >= 0; i--) {
    mpn_montmul_var(rp, rp, rp, mp, mn, k, tp);

    if (mpn_getbit(yp, yn, i))
      mpn_montmul_var(rp, rp, ap, mp, mn, k, tp);
  }

  mpn_set_1(rr, mn, 1);
  mpn_montmul_var(rp, rp, rr, mp, mn, k, tp);

  if (mpn_cmp(rp, mp, mn) >= 0) {
    mpn_sub_n(rp, rp, mp, mn);

    if (mpn_cmp(rp, mp, mn) >= 0)
      mpn_mod(rp, rp, mn, mp, mn);
  }

  mpn_copyi(zp, rp, mn);
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

  mpn_copyi(rp, xp, xn);
  mpn_zero(rp + xn, mn - xn);

  mpn_mont(&k, rr, mp, mn, tp);

#define WND(i) (&wp[(i) * mn])

  mpn_set_1(WND(0), mn, 1);
  mpn_montmul(WND(0), WND(0), rr, mp, mn, k, tp);
  mpn_montmul(WND(1), rp, rr, mp, mn, k, tp);

  for (i = 2; i < MP_FIXED_SIZE; i++)
    mpn_montmul(WND(i), WND(i - 1), WND(1), mp, mn, k, tp);

  steps = ((yn * MP_LIMB_BITS) + MP_FIXED_WIDTH - 1) / MP_FIXED_WIDTH;

  mpn_copyi(rp, WND(0), mn);
  mpn_zero(sp, mn);

  for (i = steps - 1; i >= 0; i--) {
    b = mpn_getbits(yp, yn, i * MP_FIXED_WIDTH, MP_FIXED_WIDTH);

    for (j = 0; j < MP_FIXED_SIZE; j++)
      mpn_select(sp, sp, WND(j), mn, j == b);

    if (i == steps - 1) {
      mpn_copyi(rp, sp, mn);
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
  if (xn == 0)
    return 0;

  return xp[0] & 1;
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

size_t
mpn_sizeinbase(const mp_limb_t *xp, int xn, int base) {
  if (base >= 2 && (base & (base - 1)) == 0) {
    int den = mp_bitlen(base - 1);
    int len = mpn_bitlen(xp, xn);

    if (len == 0)
      return 1;

    return (len + den - 1) / den;
  }

  return mpn_get_str(NULL, xp, xn, base);
}

void
mpn_swap(mp_limb_t **xp, int *xn,
         mp_limb_t **yp, int *yn) {
  mp_limb_t *tp = *xp;
  int tn = *xn;

  *xp = *yp;
  *xn = *yn;
  *yp = tp;
  *yn = tn;
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
 * String Import
 */

int
mpn_set_str(mp_limb_t *zp, int zn, const char *str, int base) {
  mp_limb_t c;
  int shift = 0;
  int n = 0;
  int ch;

  if (str == NULL)
    goto fail;

  if (base < 2 || base > 36)
    goto fail;

  if ((base & (base - 1)) == 0)
    shift = mp_bitlen(base - 1);

  while (*str) {
    ch = *str++;

    if (mp_isspace(ch))
      continue;

    if (ch >= '0' && ch <= '9')
      ch -= '0';
    else if (ch >= 'A' && ch <= 'Z')
      ch -= 'A' - 10;
    else if (ch >= 'a' && ch <= 'z')
      ch -= 'a' - 10;
    else
      ch = base;

    if (ch >= base)
      goto fail;

    if (shift > 0) {
      if (n > 0) {
        c = mpn_lshift(zp, zp, n, shift);

        if (c != 0) {
          if (n == zn)
            goto fail;

          zp[n++] = c;
        }

        zp[0] |= ch;
      } else if (ch != 0) {
        if (n == zn)
          goto fail;

        zp[n++] = ch;
      }
    } else {
      c = mpn_mul_1(zp, zp, n, base);

      if (c != 0) {
        if (n == zn)
          goto fail;

        zp[n++] = c;
      }

      c = mpn_add_1(zp, zp, n, ch);

      if (c != 0) {
        if (n == zn)
          goto fail;

        zp[n++] = c;
      }
    }
  }

  mpn_zero(zp + n, zn - n);

  return 1;
fail:
  mpn_zero(zp, zn);
  return 0;
}

/*
 * String Export
 */

size_t
mpn_get_str(char *str, const mp_limb_t *xp, int xn, int base) {
  size_t len = 0;
  size_t i, j, k;
  int tn, sn, ch;
  mp_limb_t *tp;
  int shift = 0;

  CHECK(base >= 2 && base <= 36);

  tn = mpn_strip(xp, xn);
  sn = MP_MAX(tn, 1);
  tp = mp_alloc_vla(sn);

  mpn_copyi(tp, xp, tn);

  if (tn == 0) {
    if (str != NULL)
      str[len] = '0';

    len += 1;
  } else {
    if ((base & (base - 1)) == 0)
      shift = mp_bitlen(base - 1);

    do {
      if (shift > 0)
        ch = mpn_rshift(tp, tp, tn, shift);
      else
        ch = mpn_divmod_1(tp, tp, tn, base);

      tn -= (tp[tn - 1] == 0);

      if (str != NULL) {
        if (ch < 10)
          ch += '0';
        else
          ch += 'a' - 10;

        str[len] = ch;
      }

      len += 1;
    } while (tn != 0);
  }

  if (str != NULL) {
    i = 0;
    j = len - 1;
    k = len >> 1;

    while (k--) {
      ch = str[i];
      str[i++] = str[j];
      str[j--] = ch;
    }

    str[len] = '\0';
  }

  mp_free_vla(tp, sn);

  return len;
}

/*
 * STDIO
 */

void
mpn_print(const mp_limb_t *xp, int xn, int base, mp_puts_f *mp_puts) {
  size_t size = mpn_sizeinbase(xp, xn, base);
  char *str = mp_alloc_str(size + 1);

  CHECK(str != NULL);

  mpn_get_str(str, xp, xn, base);

  mp_puts(str);
  mp_free_str(str, size + 1);
}

/*
 * RNG
 */

void
mpn_random(mp_limb_t *zp, int zn, mp_rng_f *rng, void *arg) {
  rng(zp, zn * sizeof(mp_limb_t), arg);
}

/*
 * MPV Interface
 */

/*
 * Assignment
 */

static TORSION_INLINE int
mpv_set_1(mp_limb_t *zp, mp_limb_t x) {
  zp[0] = x;
  return x != 0;
}

static TORSION_INLINE int
mpv_set(mp_limb_t *zp, const mp_limb_t *xp, int xn) {
  mpn_copyi(zp, xp, xn);
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
  int zn = MP_MAX(xn, yn);

  if (xn >= yn)
    zp[zn] = mpn_add(zp, xp, xn, yp, yn);
  else
    zp[zn] = mpn_add(zp, yp, yn, xp, xn);

  return zn + (zp[zn] != 0);
}

/*
 * Subtraction
 */

static TORSION_INLINE int
mpv_sub_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y) {
  CHECK(mpn_sub_1(zp, xp, xn, y) == 0);

  if (xn == 0)
    return 0;

  return xn - (zp[xn - 1] == 0);
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
  ASSERT(xn != 0 && y != 0);

  zp[xn] = mpn_mul_1(zp, xp, xn, y);

  return xn + (zp[xn] != 0);
}

static TORSION_INLINE int
mpv_mul(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                       const mp_limb_t *yp, int yn) {
  int zn = xn + yn;

  ASSERT(xn != 0 && yn != 0);

  mpn_mul(zp, xp, xn, yp, yn);

  return zn - (zp[zn - 1] == 0);
}

static TORSION_INLINE int
mpv_sqr_1(mp_limb_t *zp, mp_limb_t x) {
  ASSERT(x != 0);

  mp_sqr(zp[1], zp[0], x);

  return 2 - (zp[1] == 0);
}

static TORSION_INLINE int
mpv_sqr(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t *scratch) {
  int zn = xn * 2;

  ASSERT(xn != 0);

  mpn_sqr(zp, xp, xn, scratch);

  return zn - (zp[zn - 1] == 0);
}

/*
 * Left Shift
 */

static TORSION_INLINE int
mpv_lshift(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits) {
  int s = bits / MP_LIMB_BITS;
  int r = bits % MP_LIMB_BITS;
  int zn = xn + s;

  if (xn == 0)
    return 0;

  if (r != 0) {
    zp[zn] = mpn_lshift(zp + s, xp, xn, r);
    zn += (zp[zn] != 0);
  } else if (s != 0 || zp != xp) {
    mpn_copyd(zp + s, xp, xn);
  }

  mpn_zero(zp, s);

  return zn;
}

/*
 * Right Shift
 */

static TORSION_INLINE int
mpv_rshift(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits) {
  int s = bits / MP_LIMB_BITS;
  int r = bits % MP_LIMB_BITS;
  int zn = xn - s;

  if (zn <= 0)
    return 0;

  if (r != 0) {
    mpn_rshift(zp, xp + s, zn, r);
    zn -= (zp[zn - 1] == 0);
  } else if (s != 0 || zp != xp) {
    mpn_copyi(zp, xp + s, zn);
  }

  return zn;
}

/*
 * MPZ Interface
 */

/*
 * Initialization
 */

void
mpz_init(mpz_t z) {
  z->limbs = mp_alloc_limbs(1);
  z->limbs[0] = 0;
  z->alloc = 1;
  z->size = 0;
}

void
mpz_init_set(mpz_t z, const mpz_t x) {
  mpz_init(z);
  mpz_set(z, x);
}

void
mpz_init_set_ui(mpz_t z, mp_limb_t x) {
  mpz_init(z);
  mpz_set_ui(z, x);
}

void
mpz_init_set_si(mpz_t z, mp_long_t x) {
  mpz_init(z);
  mpz_set_si(z, x);
}

int
mpz_init_set_str(mpz_t z, const char *str, int base) {
  mpz_init(z);
  return mpz_set_str(z, str, base);
}

/*
 * Uninitialization
 */

void
mpz_clear(mpz_t z) {
  if (z->alloc > 0)
    mp_free_limbs(z->limbs);

  z->limbs = NULL;
  z->alloc = 0;
  z->size = 0;
}

void
mpz_cleanse(mpz_t z) {
  if (z->alloc > 0)
    mpn_cleanse(z->limbs, z->alloc);

  mpz_clear(z);
}

/*
 * Internal
 */

static void
mpz_grow(mpz_t z, int size) {
  if (size > z->alloc) {
    z->limbs = mp_realloc_limbs(z->limbs, size);
    z->alloc = size;
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

    mpn_copyi(z->limbs, x->limbs, xn);

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
mpz_roinit_n(mpz_t z, const mp_limb_t *xp, int xs) {
  int zn = mpn_strip(xp, MP_ABS(xs));

  z->limbs = (mp_limb_t *)xp;
  z->alloc = 0;
  z->size = xs < 0 ? -zn : zn;
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
mpz_set_si(mpz_t z, mp_long_t x) {
  if (x == 0) {
    z->size = 0;
  } else {
    mpz_grow(z, 1);

    z->limbs[0] = mp_long_abs(x);
    z->size = x < 0 ? -1 : 1;
  }
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

mp_long_t
mpz_get_si(const mpz_t x) {
  return mp_limb_cast(mpz_get_ui(x), x->size < 0);
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
  if (x->size != y->size)
    return x->size < y->size ? -1 : 1;

  if (x->size < 0)
    return -mpn_cmp(x->limbs, y->limbs, -x->size);

  return mpn_cmp(x->limbs, y->limbs, x->size);
}

int
mpz_cmp_ui(const mpz_t x, mp_limb_t y) {
  if (x->size < 0)
    return -1;

  return mpv_cmp_1(x->limbs, x->size, y);
}

int
mpz_cmp_si(const mpz_t x, mp_long_t y) {
  if (y < 0) {
    if (x->size < 0)
      return -mpz_cmpabs_si(x, y);

    return 1;
  }

  return mpz_cmp_ui(x, y);
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

int
mpz_cmpabs_si(const mpz_t x, mp_long_t y) {
  return mpv_cmp_1(x->limbs, MP_ABS(x->size), mp_long_abs(y));
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
    int cmp = mpz_cmpabs(x, y);

    if (cmp == 0) {
      /* x + (-x) == 0 */
      /* (-x) + x == 0 */
      z->size = 0;
      return;
    }

    if (cmp < 0) {
      /* x + (-y) == -(y - x) */
      /* (-x) + y == y - x */
      zn = -mpv_sub(z->limbs, y->limbs, yn, x->limbs, xn);
    } else {
      /* x + (-y) == x - y */
      /* (-x) + y == -(x - y) */
      zn = mpv_sub(z->limbs, x->limbs, xn, y->limbs, yn);
    }
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
    zn = mpv_add_1(z->limbs, x->limbs, xn, y);
  } else {
    if (xn == 1 && x->limbs[0] < y) {
      /* (-x) + y == y - x */
      z->limbs[0] = y - x->limbs[0];
      zn = -1;
    } else {
      /* (-x) + y == -(x - y) */
      zn = mpv_sub_1(z->limbs, x->limbs, xn, y);
    }
  }

  z->size = x->size < 0 ? -zn : zn;
}

void
mpz_add_si(mpz_t z, const mpz_t x, mp_long_t y) {
  if (y < 0)
    mpz_sub_ui(z, x, mp_long_abs(y));
  else
    mpz_add_ui(z, x, y);
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
    int cmp = mpz_cmpabs(x, y);

    if (cmp == 0) {
      /* x - x == 0 */
      /* (-x) - (-x) == 0 */
      z->size = 0;
      return;
    }

    if (cmp < 0) {
      /* x - y == -(y - x) */
      /* (-x) - (-y) == y - x */
      zn = -mpv_sub(z->limbs, y->limbs, yn, x->limbs, xn);
    } else {
      /* x - y == x - y */
      /* (-x) - (-y) == -(x - y) */
      zn = mpv_sub(z->limbs, x->limbs, xn, y->limbs, yn);
    }
  }

  z->size = x->size < 0 ? -zn : zn;
}

void
mpz_sub_ui(mpz_t z, const mpz_t x, mp_limb_t y) {
  int xn = MP_ABS(x->size);
  int zn = MP_MAX(xn, 1) + 1;

  mpz_grow(z, zn);

  if (x->size < 0) {
    /* (-x) - y == -(x + y) */
    zn = mpv_add_1(z->limbs, x->limbs, xn, y);
  } else {
    if (xn == 0) {
      /* 0 - y == -(y) */
      z->limbs[0] = y;
      zn = -(y != 0);
    } else if (xn == 1 && x->limbs[0] < y) {
      /* x - y == -(y - x) */
      z->limbs[0] = y - x->limbs[0];
      zn = -1;
    } else {
      /* x - y == x - y */
      zn = mpv_sub_1(z->limbs, x->limbs, xn, y);
    }
  }

  z->size = x->size < 0 ? -zn : zn;
}

void
mpz_sub_si(mpz_t z, const mpz_t x, mp_long_t y) {
  if (y < 0)
    mpz_add_ui(z, x, mp_long_abs(y));
  else
    mpz_sub_ui(z, x, y);
}

void
mpz_ui_sub(mpz_t z, mp_limb_t x, const mpz_t y) {
  int yn = MP_ABS(y->size);
  int zn = MP_MAX(1, yn) + 1;

  mpz_grow(z, zn);

  if (y->size < 0) {
    /* x - (-y) == y + x */
    zn = mpv_add_1(z->limbs, y->limbs, yn, x);
  } else {
    if (yn == 0) {
      /* x - 0 == x */
      z->limbs[0] = x;
      zn = (x != 0);
    } else if (yn == 1 && x >= y->limbs[0]) {
      /* x - y == x - y */
      z->limbs[0] = x - y->limbs[0];
      zn = (z->limbs[0] != 0);
    } else {
      /* x - y == -(y - x) */
      zn = -mpv_sub_1(z->limbs, y->limbs, yn, x);
    }
  }

  z->size = zn;
}

void
mpz_si_sub(mpz_t z, mp_long_t x, const mpz_t y) {
  mp_limb_t u = mp_long_abs(x);

  if (x < 0) {
    if (y->size < 0) {
      /* (-x) - (-y) == y - x */
      mpz_neg(z, y);
      mpz_sub_ui(z, z, u);
    } else {
      /* (-x) - y == -(y + x) */
      mpz_add_ui(z, y, u);
      mpz_neg(z, z);
    }
  } else {
    mpz_ui_sub(z, u, y);
  }
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

    mpn_copyi(z->limbs, tp, zn);

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
  zn = xn + 1;

  mpz_grow(z, zn);

  zn = mpv_mul_1(z->limbs, x->limbs, xn, y);

  z->size = x->size < 0 ? -zn : zn;
}

void
mpz_mul_si(mpz_t z, const mpz_t x, mp_long_t y) {
  mpz_mul_ui(z, x, mp_long_abs(y));

  if (y < 0)
    mpz_neg(z, z);
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
    zn = mpv_sqr_1(z->limbs, x->limbs[0]);
  } else if (z == x) {
    tn = zn * 2;
    tp = mp_alloc_vla(tn);
    zn = mpv_sqr(tp, x->limbs, xn, tp + zn);

    mpn_copyi(z->limbs, tp, zn);

    mp_free_vla(tp, tn);
  } else if (zn <= mp_alloca_max) {
    tn = zn;
    tp = mp_alloc_vla(tn);
    zn = mpv_sqr(z->limbs, x->limbs, xn, tp);

    mp_free_vla(tp, tn);
  } else {
    zn = mpv_mul(z->limbs, x->limbs, xn, x->limbs, xn);
  }

  z->size = zn;
}

void
mpz_addmul(mpz_t z, const mpz_t x, const mpz_t y) {
  mpz_t xy;
  mpz_init(xy);
  mpz_mul(xy, x, y);
  mpz_add(z, z, xy);
  mpz_clear(xy);
}

void
mpz_addmul_ui(mpz_t z, const mpz_t x, mp_limb_t y) {
  mpz_t xy;
  mpz_init(xy);
  mpz_mul_ui(xy, x, y);
  mpz_add(z, z, xy);
  mpz_clear(xy);
}

void
mpz_addmul_si(mpz_t z, const mpz_t x, mp_long_t y) {
  if (y < 0)
    mpz_submul_ui(z, x, mp_long_abs(y));
  else
    mpz_addmul_ui(z, x, y);
}

void
mpz_submul(mpz_t z, const mpz_t x, const mpz_t y) {
  mpz_t xy;
  mpz_init(xy);
  mpz_mul(xy, x, y);
  mpz_sub(z, z, xy);
  mpz_clear(xy);
}

void
mpz_submul_ui(mpz_t z, const mpz_t x, mp_limb_t y) {
  mpz_t xy;
  mpz_init(xy);
  mpz_mul_ui(xy, x, y);
  mpz_sub(z, z, xy);
  mpz_clear(xy);
}

void
mpz_submul_si(mpz_t z, const mpz_t x, mp_long_t y) {
  if (y < 0)
    mpz_addmul_ui(z, x, mp_long_abs(y));
  else
    mpz_submul_ui(z, x, y);
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
    if (q != NULL)
      q->size = 0;

    if (r != NULL)
      r->size = 0;

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
      qn = nn - (qp[nn - 1] == 0);
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

static mp_long_t
mpz_div_si_inner(mpz_t q, const mpz_t n, mp_long_t d, int euclid) {
  int nn = MP_ABS(n->size);
  int qs = (n->size < 0) ^ (d < 0);
  int rs = n->size < 0;
  mp_limb_t *qp = NULL;
  mp_long_t r;
  int qn = 0;

  if (d == 0)
    torsion_abort(); /* LCOV_EXCL_LINE */

  if (nn == 0) {
    if (q != NULL)
      q->size = 0;

    return 0;
  }

  if (mpz_cmpabs_si(n, d) < 0) {
    r = n->limbs[0];

    if (q != NULL)
      q->size = 0;
  } else {
    if (q != NULL) {
      mpz_grow(q, nn);
      qp = q->limbs;
    }

    r = mpn_divmod_1(qp, n->limbs, nn, mp_long_abs(d));

    if (q != NULL)
      qn = nn - (qp[nn - 1] == 0);
  }

  if (q != NULL)
    q->size = qs ? -qn : qn;

  r = rs ? -r : r;

  if (euclid) {
    if (q != NULL) {
      if (r < 0) {
        if (d < 0)
          mpz_add_ui(q, q, 1);
        else
          mpz_sub_ui(q, q, 1);
      }
    }

    if (r < 0) {
      if (d < 0)
        r -= d;
      else
        r += d;
    }
  }

  return r;
}

/*
 * Truncation Division
 */

void
mpz_quorem(mpz_t q, mpz_t r, const mpz_t n, const mpz_t d) {
  CHECK(q != NULL && r != NULL);
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
  CHECK(q != NULL);
  return mpz_div_ui_inner(q, n, d, 0);
}

mp_limb_t
mpz_rem_ui(const mpz_t n, mp_limb_t d) {
  return mpz_div_ui_inner(NULL, n, d, 0);
}

mp_long_t
mpz_quo_si(mpz_t q, const mpz_t n, mp_long_t d) {
  CHECK(q != NULL);
  return mpz_div_si_inner(q, n, d, 0);
}

mp_long_t
mpz_rem_si(const mpz_t n, mp_long_t d) {
  return mpz_div_si_inner(NULL, n, d, 0);
}

/*
 * Euclidean Division
 */

void
mpz_divmod(mpz_t q, mpz_t r, const mpz_t n, const mpz_t d) {
  CHECK(q != NULL && r != NULL);
  mpz_div_inner(q, r, n, d, 1);
}

void
mpz_div(mpz_t q, const mpz_t n, const mpz_t d) {
  mpz_t r;

  CHECK(q != NULL);

  if (n->size < 0) {
    mpz_init(r);
    mpz_div_inner(q, r, n, d, 1);
    mpz_clear(r);
  } else {
    mpz_div_inner(q, NULL, n, d, 0);
  }
}

void
mpz_mod(mpz_t r, const mpz_t n, const mpz_t d) {
  mpz_div_inner(NULL, r, n, d, 1);
}

mp_limb_t
mpz_div_ui(mpz_t q, const mpz_t n, mp_limb_t d) {
  CHECK(q != NULL);
  return mpz_div_ui_inner(q, n, d, 1);
}

mp_limb_t
mpz_mod_ui(const mpz_t n, mp_limb_t d) {
  return mpz_div_ui_inner(NULL, n, d, 1);
}

mp_long_t
mpz_div_si(mpz_t q, const mpz_t n, mp_long_t d) {
  CHECK(q != NULL);
  return mpz_div_si_inner(q, n, d, 1);
}

mp_long_t
mpz_mod_si(const mpz_t n, mp_long_t d) {
  return mpz_div_si_inner(NULL, n, d, 1);
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

void
mpz_divexact_si(mpz_t q, const mpz_t n, mp_long_t d) {
  CHECK(mpz_div_si_inner(q, n, d, 0) == 0);
}

/*
 * Divisibility
 */

int
mpz_divisible_p(const mpz_t n, const mpz_t d) {
  mpz_t r;
  int ret;

  if (d->size == 0)
    return n->size == 0;

  mpz_init(r);
  mpz_rem(r, n, d);

  ret = (r->size == 0);

  mpz_clear(r);

  return ret;
}

int
mpz_divisible_ui_p(const mpz_t n, mp_limb_t d) {
  if (d == 0)
    return n->size == 0;

  return mpz_rem_ui(n, d) == 0;
}

int
mpz_divisible_2exp_p(const mpz_t n, int bits) {
  int s = bits / MP_LIMB_BITS;
  int r;

  if (s >= MP_ABS(n->size))
    return n->size >= 0;

  r = bits % MP_LIMB_BITS;

  if (n->limbs[s] & MP_MASK(r))
    return 0;

  while (s--) {
    if (n->limbs[s] != 0)
      return 0;
  }

  return 1;
}

/*
 * Round Division
 */

void
mpz_divround(mpz_t q, const mpz_t n, const mpz_t d) {
  /* Computes q = (n +- (d >> 1)) / d. */
  mpz_t t;

  mpz_init(t);

  mpz_quo_2exp(t, d, 1);

  if ((n->size < 0) ^ (d->size < 0))
    mpz_sub(t, n, t);
  else
    mpz_add(t, n, t);

  mpz_quo(q, t, d);

  mpz_clear(t);
}

/*
 * Exponentiation
 */

void
mpz_pow_ui(mpz_t z, const mpz_t x, mp_limb_t y) {
  mpz_t u;

  mpz_init(u);

  mpz_set(u, x);
  mpz_set_ui(z, 1);

  while (y > 0) {
    if (y & 1)
      mpz_mul(z, z, u);

    mpz_sqr(u, u);

    y >>= 1;
  }

  mpz_clear(u);
}

void
mpz_ui_pow_ui(mpz_t z, mp_limb_t x, mp_limb_t y) {
  mpz_set_ui(z, x);
  mpz_pow_ui(z, z, y);
}

/*
 * Roots
 */

void
mpz_sqrtrem(mpz_t z, mpz_t r, const mpz_t x) {
  /* Integer Square Root.
   *
   * [ARITH] Algorithm 1.13, Page 27, Section 1.5
   */
  mpz_t u, s;

  if (x->size < 0)
    torsion_abort(); /* LCOV_EXCL_LINE */

  if (x->size == 0) {
    if (z != NULL)
      z->size = 0;

    if (r != NULL)
      r->size = 0;

    return;
  }

  mpz_init(u);
  mpz_init(s);

  /* u >= floor(x^(1/2)) */
  mpz_setbit(u, mpz_bitlen(x) / 2 + 1);

  do {
    mpz_swap(s, u);
    mpz_quo(u, x, s);
    mpz_add(u, s, u);
    mpz_quo_2exp(u, u, 1);
  } while (mpz_cmpabs(u, s) < 0);

  if (r != NULL) {
    mpz_sqr(u, s);
    mpz_sub(r, x, u);
  }

  if (z != NULL)
    mpz_swap(z, s);

  mpz_clear(u);
  mpz_clear(s);
}

void
mpz_sqrt(mpz_t z, const mpz_t x) {
  mpz_sqrtrem(z, NULL, x);
}

int
mpz_perfect_square_p(const mpz_t x) {
  mpz_t r;
  int ret;

  if (x->size < 0)
    return 0;

  mpz_init(r);

  mpz_sqrtrem(NULL, r, x);

  ret = (r->size == 0);

  mpz_clear(r);

  return ret;
}

/*
 * Unsigned AND
 */

static void
mpz_and_abs(mpz_t z, const mpz_t x, const mpz_t y) {
  int xn = MP_ABS(x->size);
  int yn = MP_ABS(y->size);
  int zn = MP_MIN(xn, yn);

  mpz_grow(z, zn);

  mpn_and_n(z->limbs, x->limbs, y->limbs, zn);

  zn = mpn_strip(z->limbs, zn);

  z->size = ((x->size < 0) & (y->size < 0)) ? -zn : zn;
}

/*
 * Unsigned AND+NOT
 */

static void
mpz_andn_abs(mpz_t z, const mpz_t x, const mpz_t y) {
  int xn = MP_ABS(x->size);
  int yn = MP_ABS(y->size);
  int zn = xn;

  mpz_grow(z, zn);

  mpn_andn(z->limbs, x->limbs, xn, y->limbs, yn);

  zn = mpn_strip(z->limbs, zn);

  z->size = ((x->size < 0) & !(y->size < 0)) ? -zn : zn;
}

static void
mpz_andn_1(mpz_t z, const mpz_t x, mp_limb_t y) {
  int xn = MP_ABS(x->size);
  int zn;

  if (xn == 0) {
    zn = 0;
  } else {
    mpz_set(z, x);

    z->limbs[0] &= ~y;
    zn = xn - (z->limbs[xn - 1] == 0);
  }

  z->size = x->size < 0 ? -zn : zn;
}

/*
 * Unsigned OR
 */

static void
mpz_ior_abs(mpz_t z, const mpz_t x, const mpz_t y) {
  int xn = MP_ABS(x->size);
  int yn = MP_ABS(y->size);
  int zn = MP_MAX(xn, yn);

  mpz_grow(z, zn);

  if (xn >= yn)
    mpn_ior(z->limbs, x->limbs, xn, y->limbs, yn);
  else
    mpn_ior(z->limbs, y->limbs, yn, x->limbs, xn);

  zn = mpn_strip(z->limbs, zn);

  z->size = ((x->size < 0) | (y->size < 0)) ? -zn : zn;
}

static void
mpz_ior_1(mpz_t z, const mpz_t x, mp_limb_t y) {
  int xn = MP_ABS(x->size);
  int zn;

  if (xn == 0) {
    mpz_grow(z, 1);

    z->limbs[0] = y;
    zn = (y != 0);
  } else {
    mpz_set(z, x);

    z->limbs[0] |= y;
    zn = xn;
  }

  z->size = x->size < 0 ? -zn : zn;
}

/*
 * Unsigned XOR
 */

static void
mpz_xor_abs(mpz_t z, const mpz_t x, const mpz_t y) {
  int xn = MP_ABS(x->size);
  int yn = MP_ABS(y->size);
  int zn = MP_MAX(xn, yn);

  mpz_grow(z, zn);

  if (xn >= yn)
    mpn_xor(z->limbs, x->limbs, xn, y->limbs, yn);
  else
    mpn_xor(z->limbs, y->limbs, yn, x->limbs, xn);

  zn = mpn_strip(z->limbs, zn);

  z->size = ((x->size < 0) ^ (y->size < 0)) ? -zn : zn;
}

static void
mpz_xor_1(mpz_t z, const mpz_t x, mp_limb_t y) {
  int xn = MP_ABS(x->size);
  int zn;

  if (xn == 0) {
    mpz_grow(z, 1);

    z->limbs[0] = y;
    zn = (y != 0);
  } else {
    mpz_set(z, x);

    z->limbs[0] ^= y;
    zn = xn - (z->limbs[xn - 1] == 0);
  }

  z->size = x->size < 0 ? -zn : zn;
}

/*
 * Unsigned Left Shift
 */

static void
mpz_lshift_abs(mpz_t z, const mpz_t x, int bits) {
  int xn, zn;

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
 * Unsigned Right Shift
 */

static void
mpz_rshift_abs(mpz_t z, const mpz_t x, int bits) {
  int xn, zn;

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
 * Unsigned Bit Manipulation
 */

static void
mpz_setbit_abs(mpz_t z, int pos) {
  int index = pos / MP_LIMB_BITS;
  int zn = MP_ABS(z->size);

  if (zn < index + 1) {
    mpz_grow(z, index + 1);

    while (zn < index + 1)
      z->limbs[zn++] = 0;

    z->size = z->size < 0 ? -zn : zn;
  }

  z->limbs[index] |= MP_LIMB_C(1) << (pos % MP_LIMB_BITS);
}

static void
mpz_clrbit_abs(mpz_t z, int pos) {
  int index = pos / MP_LIMB_BITS;
  int zn = MP_ABS(z->size);

  if (index < zn) {
    z->limbs[index] &= ~(MP_LIMB_C(1) << (pos % MP_LIMB_BITS));

    zn = mpn_strip(z->limbs, zn);

    z->size = z->size < 0 ? -zn : zn;
  }
}

/*
 * AND
 */

void
mpz_and(mpz_t z, const mpz_t x, const mpz_t y) {
  mpz_t u, v;

  if (x->size >= 0 && y->size >= 0) {
    mpz_and_abs(z, x, y);
    return;
  }

  mpz_init(u);
  mpz_init(v);

  mpz_abs(u, x);
  mpz_abs(v, y);

  if (x->size < 0 && y->size < 0) {
    /* (-x) & (-y) == ~(x-1) & ~(y-1)
     *             == ~((x-1) | (y-1))
     *             == -(((x-1) | (y-1)) + 1)
     */
    mpz_sub_ui(u, u, 1);
    mpz_sub_ui(v, v, 1);
    mpz_ior_abs(z, u, v);
    mpz_add_ui(z, z, 1);
    mpz_neg(z, z);
  } else {
    if (x->size < 0)
      mpz_swap(u, v);

    /* x & (-y) == x & ~(y-1) */
    mpz_sub_ui(v, v, 1);
    mpz_andn_abs(z, u, v);
  }

  mpz_clear(u);
  mpz_clear(v);
}

mp_limb_t
mpz_and_ui(const mpz_t x, mp_limb_t y) {
  if (x->size < 0) {
    /* (-x) & y == y & ~(x-1) */
    return y & ~(x->limbs[0] - 1);
  }

  if (x->size == 0)
    return 0;

  return x->limbs[0] & y;
}

void
mpz_and_si(mpz_t z, const mpz_t x, mp_long_t y) {
  mp_limb_t v = mp_long_abs(y);

  if (y < 0) {
    if (x->size < 0) {
      /* (-x) & (-y) == ~(x-1) & ~(y-1)
       *             == ~((x-1) | (y-1))
       *             == -(((x-1) | (y-1)) + 1)
       */
      mpz_neg(z, x);
      mpz_sub_ui(z, z, 1);
      mpz_ior_1(z, z, v - 1);
      mpz_add_ui(z, z, 1);
      mpz_neg(z, z);
    } else {
      /* x & (-y) == x & ~(y-1) */
      mpz_andn_1(z, x, v - 1);
    }
  } else {
    mpz_set_ui(z, mpz_and_ui(x, v));
  }
}

/*
 * OR
 */

void
mpz_ior(mpz_t z, const mpz_t x, const mpz_t y) {
  mpz_t u, v;

  if (x->size >= 0 && y->size >= 0) {
    mpz_ior_abs(z, x, y);
    return;
  }

  mpz_init(u);
  mpz_init(v);

  mpz_abs(u, x);
  mpz_abs(v, y);

  if (x->size < 0 && y->size < 0) {
    /* (-x) | (-y) == ~(x-1) | ~(y-1)
     *             == ~((x-1) & (y-1))
     *             == -(((x-1) & (y-1)) + 1)
     */
    mpz_sub_ui(u, u, 1);
    mpz_sub_ui(v, v, 1);
    mpz_and_abs(z, u, v);
    mpz_add_ui(z, z, 1);
    mpz_neg(z, z);
  } else {
    if (x->size < 0)
      mpz_swap(u, v);

    /* x | (-y) == x | ~(y-1)
     *          == ~((y-1) & ~x)
     *          == -(((y-1) & ~x) + 1)
     */
    mpz_sub_ui(v, v, 1);
    mpz_andn_abs(z, v, u);
    mpz_add_ui(z, z, 1);
    mpz_neg(z, z);
  }

  mpz_clear(u);
  mpz_clear(v);
}

void
mpz_ior_ui(mpz_t z, const mpz_t x, mp_limb_t y) {
  if (x->size < 0) {
    /* (-x) | y == y | ~(x-1)
     *          == ~((x-1) & ~y)
     *          == -(((x-1) & ~y) + 1)
     */
    mpz_neg(z, x);
    mpz_sub_ui(z, z, 1);
    mpz_andn_1(z, z, y);
    mpz_add_ui(z, z, 1);
    mpz_neg(z, z);
  } else {
    mpz_ior_1(z, x, y);
  }
}

void
mpz_ior_si(mpz_t z, const mpz_t x, mp_long_t y) {
  mp_limb_t v = mp_long_abs(y);
  mp_limb_t r;

  if (y < 0) {
    if (x->size < 0) {
      /* (-x) | (-y) == ~(x-1) | ~(y-1)
       *             == ~((x-1) & (y-1))
       *             == -(((x-1) & (y-1)) + 1)
       */
      r = ((x->limbs[0] - 1) & (v - 1)) + 1;
    } else if (x->size > 0) {
      /* x | (-y) == x | ~(y-1)
       *          == ~((y-1) & ~x)
       *          == -(((y-1) & ~x) + 1)
       */
      r = ((v - 1) & ~x->limbs[0]) + 1;
    } else {
      /* 0 | (-y) == -(y) */
      r = v;
    }

    mpz_set_si(z, mp_limb_cast(r, 1));
  } else {
    mpz_ior_ui(z, x, v);
  }
}

/*
 * XOR
 */

void
mpz_xor(mpz_t z, const mpz_t x, const mpz_t y) {
  mpz_t u, v;

  if (x->size >= 0 && y->size >= 0) {
    mpz_xor_abs(z, x, y);
    return;
  }

  mpz_init(u);
  mpz_init(v);

  mpz_abs(u, x);
  mpz_abs(v, y);

  if (x->size < 0 && y->size < 0) {
    /* (-x) ^ (-y) == ~(x-1) ^ ~(y-1)
     *             == (x-1) ^ (y-1)
     */
    mpz_sub_ui(u, u, 1);
    mpz_sub_ui(v, v, 1);
    mpz_xor_abs(z, u, v);
  } else {
    if (x->size < 0)
      mpz_swap(u, v);

    /* x ^ (-y) == x ^ ~(y-1)
     *          == ~(x ^ (y-1))
     *          == -((x ^ (y-1)) + 1)
     */
    mpz_sub_ui(v, v, 1);
    mpz_xor_abs(z, u, v);
    mpz_add_ui(z, z, 1);
    mpz_neg(z, z);
  }

  mpz_clear(u);
  mpz_clear(v);
}

void
mpz_xor_ui(mpz_t z, const mpz_t x, mp_limb_t y) {
  if (x->size < 0) {
    /* (-x) ^ y == y ^ ~(x-1)
     *          == ~(y ^ (x-1))
     *          == -((y ^ (x-1)) + 1)
     */
    mpz_neg(z, x);
    mpz_sub_ui(z, z, 1);
    mpz_xor_1(z, z, y);
    mpz_add_ui(z, z, 1);
    mpz_neg(z, z);
  } else {
    mpz_xor_1(z, x, y);
  }
}

void
mpz_xor_si(mpz_t z, const mpz_t x, mp_long_t y) {
  mp_limb_t v = mp_long_abs(y);

  if (y < 0) {
    if (x->size < 0) {
      /* (-x) ^ (-y) == ~(x-1) ^ ~(y-1)
       *             == (x-1) ^ (y-1)
       */
      mpz_neg(z, x);
      mpz_sub_ui(z, z, 1);
      mpz_xor_1(z, z, v - 1);
    } else {
      /* x ^ (-y) == x ^ ~(y-1)
       *          == ~(x ^ (y-1))
       *          == -((x ^ (y-1)) + 1)
       */
      mpz_xor_1(z, x, v - 1);
      mpz_add_ui(z, z, 1);
      mpz_neg(z, z);
    }
  } else {
    mpz_xor_ui(z, x, v);
  }
}

/*
 * NOT
 */

void
mpz_com(mpz_t z, const mpz_t x) {
  if (x->size < 0) {
    /* ~(-x) == ~(~(x-1)) == x-1 */
    mpz_neg(z, x);
    mpz_sub_ui(z, z, 1);
  } else {
    /* ~x == -x-1 == -(x+1) */
    mpz_add_ui(z, x, 1);
    mpz_neg(z, z);
  }
}

/*
 * Left Shift
 */

void
mpz_mul_2exp(mpz_t z, const mpz_t x, int bits) {
  mpz_lshift_abs(z, x, bits);
}

/*
 * Unsigned Right Shift
 */

void
mpz_quo_2exp(mpz_t z, const mpz_t x, int bits) {
  mpz_rshift_abs(z, x, bits);
}

void
mpz_rem_2exp(mpz_t z, const mpz_t x, int bits) {
  int xn = MP_ABS(x->size);

  mpz_grow(z, xn);

  /* x mod y == x & (y-1) */
  mpn_mask(z->limbs, x->limbs, xn, bits);

  z->size = mpn_strip(z->limbs, xn);
}

/*
 * Right Shift
 */

void
mpz_div_2exp(mpz_t z, const mpz_t x, int bits) {
  if (x->size < 0) {
    /* (-x) >> y == ~(x-1) >> y
     *           == ~((x-1) >> y)
     *           == -(((x-1) >> y) + 1)
     */
    mpz_neg(z, x);
    mpz_sub_ui(z, z, 1);
    mpz_rshift_abs(z, z, bits);
    mpz_add_ui(z, z, 1);
    mpz_neg(z, z);
  } else {
    mpz_rshift_abs(z, x, bits);
  }
}

void
mpz_mod_2exp(mpz_t z, const mpz_t x, int bits) {
  int xn = MP_ABS(x->size);
  int zn, lo;

  if (x->size < 0) {
    zn = (bits + MP_LIMB_BITS - 1) / MP_LIMB_BITS;
    lo = bits % MP_LIMB_BITS;

    mpz_grow(z, zn);

    /* (-x) mod y == (-x) & (y-1)
     *            == (y-1) & ~(x-1)
     */
    if (zn > xn) {
      mpn_sub_1(z->limbs, x->limbs, xn, 1);
      mpn_zero(z->limbs + xn, zn - xn);
    } else {
      mpn_sub_1(z->limbs, x->limbs, zn, 1);
    }

    mpn_com(z->limbs, z->limbs, zn);

    if (lo != 0)
      z->limbs[zn - 1] &= MP_MASK(lo);
  } else {
    zn = xn;

    mpz_grow(z, zn);

    /* x mod y == x & (y-1) */
    mpn_mask(z->limbs, x->limbs, xn, bits);
  }

  z->size = mpn_strip(z->limbs, zn);
}

/*
 * Bit Manipulation
 */

int
mpz_tstbit(const mpz_t x, int pos) {
  int s = pos / MP_LIMB_BITS;
  int b;

  if (s >= MP_ABS(x->size))
    return x->size < 0;

  b = (x->limbs[s] >> (pos % MP_LIMB_BITS)) & 1;

  if (x->size < 0)
    b ^= !mpz_divisible_2exp_p(x, pos);

  return b;
}

void
mpz_setbit(mpz_t z, int pos) {
  if (z->size < 0) {
    mpz_neg(z, z);
    mpz_sub_ui(z, z, 1);
    mpz_clrbit_abs(z, pos);
    mpz_add_ui(z, z, 1);
    mpz_neg(z, z);
  } else {
    mpz_setbit_abs(z, pos);
  }
}

void
mpz_clrbit(mpz_t z, int pos) {
  if (z->size < 0) {
    mpz_neg(z, z);
    mpz_sub_ui(z, z, 1);
    mpz_setbit_abs(z, pos);
    mpz_add_ui(z, z, 1);
    mpz_neg(z, z);
  } else {
    mpz_clrbit_abs(z, pos);
  }
}

void
mpz_combit(mpz_t z, int pos) {
  if (!mpz_tstbit(z, pos))
    mpz_setbit(z, pos);
  else
    mpz_clrbit(z, pos);
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
  mpz_t u, v;
  int shift;

  if (x->size == 0) {
    mpz_abs(z, y);
    return;
  }

  if (y->size == 0) {
    mpz_abs(z, x);
    return;
  }

  mpz_init(u);
  mpz_init(v);

  mpz_abs(u, x);
  mpz_abs(v, y);

  shift = mpz_ctz_common(u, v);

  mpz_quo_2exp(u, u, shift);
  mpz_quo_2exp(v, v, shift);

  while (u->size != 0) {
    mpz_quo_2exp(u, u, mpz_ctz(u));
    mpz_quo_2exp(v, v, mpz_ctz(v));

    if (mpz_cmpabs(u, v) >= 0)
      mpz_sub(u, u, v);
    else
      mpz_sub(v, v, u);
  }

  mpz_mul_2exp(z, v, shift);

  mpz_clear(u);
  mpz_clear(v);
}

mp_limb_t
mpz_gcd_ui(mpz_t z, const mpz_t x, mp_limb_t y) {
  mp_limb_t g;
  mpz_t v;

  mpz_init(v);
  mpz_set_ui(v, y);

  mpz_gcd(v, x, v);

  if (v->size <= 1)
    g = mpz_get_ui(v);
  else
    g = 0;

  if (z != NULL)
    mpz_swap(z, v);

  mpz_clear(v);

  return g;
}

void
mpz_lcm(mpz_t z, const mpz_t x, const mpz_t y) {
  mpz_t g, q;

  if (x->size == 0 || y->size == 0) {
    z->size = 0;
    return;
  }

  mpz_init(g);
  mpz_init(q);

  mpz_gcd(g, x, y);
  mpz_divexact(q, x, g);
  mpz_mul(z, y, q);
  mpz_abs(z, z);

  mpz_clear(g);
  mpz_clear(q);
}

void
mpz_lcm_ui(mpz_t z, const mpz_t x, mp_limb_t y) {
  mp_limb_t g, q;

  if (x->size == 0 || y == 0) {
    z->size = 0;
    return;
  }

  g = mpz_gcd_ui(NULL, x, y);
  q = y / g;

  CHECK(y % g == 0);

  mpz_mul_ui(z, x, q);
  mpz_abs(z, z);
}

void
mpz_gcdext(mpz_t g, mpz_t s, mpz_t t, const mpz_t x, const mpz_t y) {
  /* Euclid's algorithm for large numbers.
   *
   * [KNUTH] Algorithm L, Page 347, Section 4.5.2.
   */
  mpz_t u, v, A, B, C, D, up, vp;
  int i, j, shift;

  if (x->size == 0) {
    if (g != NULL)
      mpz_abs(g, y);

    if (s != NULL)
      s->size = 0;

    if (t != NULL)
      mpz_set_si(t, mpz_sgn(y));

    return;
  }

  if (y->size == 0) {
    if (g != NULL)
      mpz_abs(g, x);

    if (s != NULL)
      mpz_set_si(s, mpz_sgn(x));

    if (t != NULL)
      t->size = 0;

    return;
  }

  mpz_init(u);
  mpz_init(v);
  mpz_init(A);
  mpz_init(B);
  mpz_init(C);
  mpz_init(D);
  mpz_init(up);
  mpz_init(vp);

  mpz_abs(u, x);
  mpz_abs(v, y);

  /* A * u + B * v = u */
  mpz_set_ui(A, 1);
  mpz_set_ui(B, 0);

  /* C * u + D * v = v */
  mpz_set_ui(C, 0);
  mpz_set_ui(D, 1);

  shift = mpz_ctz_common(u, v);

  mpz_quo_2exp(u, u, shift);
  mpz_quo_2exp(v, v, shift);

  mpz_set(up, u);
  mpz_set(vp, v);

  while (u->size != 0) {
    i = mpz_ctz(u);
    j = mpz_ctz(v);

    mpz_quo_2exp(u, u, i);
    mpz_quo_2exp(v, v, j);

    while (i--) {
      if (mpz_odd_p(A) || mpz_odd_p(B)) {
        mpz_add(A, A, vp);
        mpz_sub(B, B, up);
      }

      mpz_quo_2exp(A, A, 1);
      mpz_quo_2exp(B, B, 1);
    }

    while (j--) {
      if (mpz_odd_p(C) || mpz_odd_p(D)) {
        mpz_add(C, C, vp);
        mpz_sub(D, D, up);
      }

      mpz_quo_2exp(C, C, 1);
      mpz_quo_2exp(D, D, 1);
    }

    if (mpz_cmpabs(u, v) >= 0) {
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
    mpz_mul_2exp(g, v, shift);

  if (s != NULL)
    mpz_swap(s, C);

  if (t != NULL)
    mpz_swap(t, D);

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
  mpz_t t, g, s;
  int ret;

  if (x->size == 0 || y->size == 0) {
    z->size = 0;
    return 0;
  }

  if (mpz_cmpabs_ui(y, 1) == 0) {
    z->size = 0;
    return 0;
  }

  if (mpz_odd_p(y)) {
    if (mpz_sgn(x) < 0 || mpz_cmpabs(x, y) >= 0) {
      mpz_init(t);
      mpz_mod(t, x, y);

      ret = mpz_invert_inner(z, t, y);

      mpz_clear(t);
    } else {
      ret = mpz_invert_inner(z, x, y);
    }
  } else {
    mpz_init(g);
    mpz_init(s);

    mpz_gcdext(g, s, NULL, x, y);

    ret = (mpz_cmp_ui(g, 1) == 0);

    if (ret) {
      mpz_mod(s, s, y);
      mpz_swap(z, s);
    } else {
      z->size = 0;
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

  if (x->size < 0 && y->size < 0)
    j = -j;

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

void
mpz_powm_ui(mpz_t z, const mpz_t x, mp_limb_t y, const mpz_t m) {
  mpz_t v;

  mpz_roinit_n(v, &y, 1);
  mpz_powm(z, x, v, m);
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

int
mpz_sqrtm(mpz_t z, const mpz_t u, const mpz_t p) {
  mpz_t x, e, t, a, s, n, y, b, g;
  int i, f, k, m;
  int ret = 0;

  CHECK(z != p);

  mpz_init(x);
  mpz_init(e);
  mpz_init(t);
  mpz_init(a);
  mpz_init(s);
  mpz_init(n);
  mpz_init(y);
  mpz_init(b);
  mpz_init(g);

  /* x = u */
  mpz_set(x, u);

  /* z = 0 */
  mpz_set_ui(z, 0);

  /* if p <= 0 or p mod 2 == 0 */
  if (mpz_sgn(p) <= 0 || mpz_even_p(p))
    goto fail;

  /* if x < 0 or x >= p */
  if (mpz_sgn(x) < 0 || mpz_cmpabs(x, p) >= 0) {
    /* x = x mod p */
    mpz_mod(x, x, p);
  }

  /* if p mod 4 == 3 */
  if ((p->limbs[0] & 3) == 3) {
    /* b = x^((p + 1) / 4) mod p */
    mpz_add_ui(e, p, 1);
    mpz_quo_2exp(e, e, 2);
    mpz_powm(b, x, e, p);

    /* g = b^2 mod p */
    mpz_sqr(g, b);
    mpz_mod(g, g, p);

    /* g != x */
    if (mpz_cmp(g, x) != 0)
      goto fail;

    /* z = b */
    mpz_swap(z, b);

    goto succeed;
  }

  /* if p mod 8 == 5 */
  if ((p->limbs[0] & 7) == 5) {
    /* t = x * 2 mod p */
    mpz_mul_2exp(t, x, 1);
    mpz_mod(t, t, p);

    /* a = t^((p - 5) / 8) mod p */
    mpz_quo_2exp(e, p, 3);
    mpz_powm(a, t, e, p);

    /* b = (a^2 * t - 1) * x * a mod p */
    mpz_sqr(b, a);
    mpz_mod(b, b, p);
    mpz_mul(b, b, t);
    mpz_mod(b, b, p);
    mpz_sub_ui(b, b, 1);
    mpz_mul(b, b, x);
    mpz_mod(b, b, p);
    mpz_mul(b, b, a);
    mpz_mod(b, b, p);

    /* g = b^2 mod p */
    mpz_sqr(g, b);
    mpz_mod(g, g, p);

    /* g != x */
    if (mpz_cmp(g, x) != 0)
      goto fail;

    /* z = b */
    mpz_swap(z, b);

    goto succeed;
  }

  /* if p == 1 */
  if (mpz_cmp_ui(p, 1) == 0)
    goto fail;

  switch (mpz_jacobi(x, p)) {
    case -1:
      goto fail;
    case 0:
      goto succeed;
    case 1:
      break;
  }

  /* s = p - 1 */
  mpz_sub_ui(s, p, 1);

  /* f = s factors of 2 */
  f = mpz_ctz(s);

  /* s = s >> f */
  mpz_quo_2exp(s, s, f);

  /* n = 2 */
  mpz_set_ui(n, 2);

  /* while n^((p - 1) / 2) != -1 mod p */
  while (mpz_jacobi(n, p) != -1) {
    /* n = n + 1 */
    mpz_add_ui(n, n, 1);
  }

  /* y = x^((s + 1) / 2) mod p */
  mpz_add_ui(y, s, 1);
  mpz_quo_2exp(y, y, 1);
  mpz_powm(y, x, y, p);

  /* b = x^s mod p */
  mpz_powm(b, x, s, p);

  /* g = n^s mod p */
  mpz_powm(g, n, s, p);

  /* k = f */
  k = f;

  for (;;) {
    /* t = b */
    mpz_set(t, b);

    /* m = 0 */
    m = 0;

    /* while t != 1 */
    while (mpz_cmp_ui(t, 1) != 0) {
      /* t = t^2 mod p */
      mpz_sqr(e, t);
      mpz_mod(t, e, p);
      m += 1;
    }

    /* if m == 0 */
    if (m == 0)
      break;

    /* if m >= k */
    if (m >= k)
      goto fail;

    /* t = g^(2^(k - m - 1)) mod p */
    mpz_swap(t, g);

    for (i = 0; i < k - m - 1; i++) {
      mpz_sqr(e, t);
      mpz_mod(t, e, p);
    }

    /* g = t^2 mod p */
    mpz_sqr(g, t);
    mpz_mod(g, g, p);

    /* y = y * t mod p */
    mpz_mul(y, y, t);
    mpz_mod(y, y, p);

    /* b = b * g mod p */
    mpz_mul(b, b, g);
    mpz_mod(b, b, p);

    /* k = m */
    k = m;
  }

  /* z = y */
  mpz_swap(z, y);
succeed:
  ret = 1;
fail:
  mpz_clear(x);
  mpz_clear(e);
  mpz_clear(t);
  mpz_clear(a);
  mpz_clear(s);
  mpz_clear(n);
  mpz_clear(y);
  mpz_clear(b);
  mpz_clear(g);
  return ret;
}

int
mpz_sqrtpq(mpz_t z, const mpz_t x, const mpz_t p, const mpz_t q) {
  /* Compute x^(1 / 2) in F(p * q). */
  mpz_t sp, sq, mp, mq, u, v;
  int ret = 0;

  mpz_init(sp);
  mpz_init(sq);
  mpz_init(mp);
  mpz_init(mq);
  mpz_init(u);
  mpz_init(v);

  /* sp = x^(1 / 2) in F(p) */
  if (!mpz_sqrtm(sp, x, p))
    goto fail;

  /* sq = x^(1 / 2) in F(q) */
  if (!mpz_sqrtm(sq, x, q))
    goto fail;

  /* (mp, mq) = bezout coefficients for egcd(p, q) */
  mpz_gcdext(NULL, mp, mq, p, q);

  /* u = sq * mp * p */
  mpz_mul(u, sq, mp);
  mpz_mul(u, u, p);

  /* v = sp * mq * q */
  mpz_mul(v, sp, mq);
  mpz_mul(v, v, q);

  /* u = u + v */
  mpz_add(u, u, v);

  /* v = p * q */
  mpz_mul(v, p, q);

  /* z = u mod v */
  mpz_mod(z, u, v);

  ret = 1;
fail:
  mpz_clear(sp);
  mpz_clear(sq);
  mpz_clear(mp);
  mpz_clear(mq);
  mpz_clear(u);
  mpz_clear(v);
  return ret;
}

/*
 * Primality Testing (logic from golang)
 */

int
mpz_mr_prime_p(const mpz_t n, int reps, int force2, mp_rng_f *rng, void *arg) {
  /* Miller-Rabin Primality Test.
   *
   * [HANDBOOK] Algorithm 4.24, Page 139, Section 4.2.3.
   */
  mpz_t nm1, nm3, q, x, y, t;
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
  mpz_init(t);

  /* nm1 = n - 1 */
  mpz_sub_ui(nm1, n, 1);

  /* nm3 = nm1 - 2 */
  mpz_sub_ui(nm3, nm1, 2);

  /* k = nm1 factors of 2 */
  k = mpz_ctz(nm1);

  /* q = nm1 >> k */
  mpz_quo_2exp(q, nm1, k);

  for (i = 0; i < reps; i++) {
    if (i == reps - 1 && force2) {
      /* x = 2 */
      mpz_set_ui(x, 2);
    } else {
      /* x = random integer in [2,n-1] */
      mpz_urandomm(x, nm3, rng, arg);
      mpz_add_ui(x, x, 2);
    }

    /* y = x^q mod n */
    mpz_powm(y, x, q, n);

    /* if y == 1 or y == -1 mod n */
    if (mpz_cmp_ui(y, 1) == 0 || mpz_cmp(y, nm1) == 0)
      continue;

    for (j = 1; j < k; j++) {
      /* y = y^2 mod n */
      mpz_sqr(t, y);
      mpz_mod(y, t, n);

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
  mpz_clear(t);
  return ret;
}

int
mpz_lucas_prime_p(const mpz_t n, mp_limb_t limit) {
  /* Lucas Primality Test.
   *
   * [LUCAS] Page 1401, Section 5.
   */
  mpz_t d, s, nm2, vk, vk1, t1, t2;
  int i, j, r, t;
  int ret = 0;
  mp_limb_t p;

  /* if n <= 1 */
  if (mpz_cmp_ui(n, 1) <= 0)
    return 0;

  /* if n mod 2 == 0 */
  if (mpz_even_p(n)) {
    /* n == 2 */
    return mpz_cmp_ui(n, 2) == 0;
  }

  mpz_init(d);
  mpz_init(s);
  mpz_init(nm2);
  mpz_init(vk);
  mpz_init(vk1);
  mpz_init(t1);
  mpz_init(t2);

  /* p = 3 */
  p = 3;

  for (;;) {
    if (p > 10000) {
      /* Thought to be impossible. */
      goto fail;
    }

    if (limit != 0 && p > limit) {
      /* Enforce a limit to prevent DoS'ing. */
      goto fail;
    }

    /* d = p^2 - 4 */
    mpz_set_ui(d, p * p - 4);

    /* j = jacobi(d) in F(n) */
    j = mpz_jacobi(d, n);

    /* if d is non-square in F(n) */
    if (j == -1)
      break;

    /* if d is zero in F(n) */
    if (j == 0) {
      /* if n == p + 2 */
      if (mpz_cmp_ui(n, p + 2) == 0)
        goto succeed;
      goto fail;
    }

    if (p == 40) {
      /* if floor(n^(1 / 2))^2 == n */
      if (mpz_perfect_square_p(n))
        goto fail;
    }

    p += 1;
  }

  /* s = n + 1 */
  mpz_add_ui(s, n, 1);

  /* r = s factors of 2 */
  r = mpz_ctz(s);

  /* s >>= r */
  mpz_quo_2exp(s, s, r);

  /* nm2 = n - 2 */
  mpz_sub_ui(nm2, n, 2);

  /* vk = 2 */
  mpz_set_ui(vk, 2);

  /* vk1 = p */
  mpz_set_ui(vk1, p);

  for (i = mpz_bitlen(s); i >= 0; i--) {
    /* if floor(s / 2^i) mod 2 == 1 */
    if (mpz_tstbit(s, i)) {
      /* vk = vk * vk1 - p mod n */
      /* vk1 = vk1^2 - 2 mod n */
      mpz_mul(t1, vk, vk1);
      mpz_sub_ui(t1, t1, p);
      mpz_mod(vk, t1, n);
      mpz_sqr(t1, vk1);
      mpz_sub_ui(t1, t1, 2);
      mpz_mod(vk1, t1, n);
    } else {
      /* vk1 = vk1 * vk - p mod n */
      /* vk = vk^2 - 2 mod n */
      mpz_mul(t1, vk1, vk);
      mpz_sub_ui(t1, t1, p);
      mpz_mod(vk1, t1, n);
      mpz_sqr(t1, vk);
      mpz_sub_ui(t1, t1, 2);
      mpz_mod(vk, t1, n);
    }
  }

  /* if vk == +-2 mod n */
  if (mpz_cmp_ui(vk, 2) == 0 || mpz_cmp(vk, nm2) == 0) {
    /* if vk * p == vk1 * 2 mod n */
    mpz_mul_ui(t1, vk, p);
    mpz_mul_2exp(t2, vk1, 1);

    mpz_mod(t1, t1, n);
    mpz_mod(t2, t2, n);

    if (mpz_cmp(t1, t2) == 0)
      goto succeed;
  }

  for (t = 0; t < r - 1; t++) {
    /* if vk == 0 */
    if (mpz_sgn(vk) == 0)
      goto succeed;

    /* if vk == 2 */
    if (mpz_cmp_ui(vk, 2) == 0)
      goto fail;

    /* vk = vk^2 - 2 mod n */
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
  return ret;
}

int
mpz_probab_prime_p(const mpz_t x, int rounds, mp_rng_f *rng, void *arg) {
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

  if (mpz_sgn(x) <= 0)
    return 0;

  if (mpz_cmp_ui(x, 64) < 0)
    return (prime_mask >> mpz_get_ui(x)) & 1;

  if (mpz_even_p(x))
    return 0;

#if MP_LIMB_BITS == 64
  r = mpz_rem_ui(x, primes_a * primes_b);
  ra = r % primes_a;
  rb = r % primes_b;
#else
  ra = mpz_rem_ui(x, primes_a);
  rb = mpz_rem_ui(x, primes_b);
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

  if (!mpz_mr_prime_p(x, rounds + 1, 1, rng, arg))
    return 0;

  if (!mpz_lucas_prime_p(x, 0))
    return 0;

  return 1;
}

void
mpz_randprime(mpz_t z, int bits, mp_rng_f *rng, void *arg) {
  static const uint64_t primes[15] = { 3, 5, 7, 11, 13, 17, 19, 23,
                                       29, 31, 37, 41, 43, 47, 53 };
#if MP_LIMB_BITS == 64
  static const mp_limb_t product = MP_LIMB_C(16294579238595022365);
#else
  static const mp_limb_t product[2] = { MP_LIMB_C(0x30e94e1d),
                                        MP_LIMB_C(0xe221f97c) };
  mp_limb_t tmp[2];
#endif
  uint64_t mod, delta, m;
  size_t i;

  CHECK(bits > 1);

  for (;;) {
    mpz_urandomb(z, bits, rng, arg);

    mpz_setbit(z, bits - 1);
    mpz_setbit(z, bits - 2);
    mpz_setbit(z, 0);

    if (bits > 64) {
#if MP_LIMB_BITS == 64
      mod = mpn_mod_1(z->limbs, z->size, product);
#else
      mpn_mod(tmp, z->limbs, z->size, product, 2);
      mod = ((uint64_t)tmp[1] << 32) | tmp[0];
#endif

      for (delta = 0; delta < (UINT64_C(1) << 20); delta += 2) {
        m = mod + delta;

        for (i = 0; i < ARRAY_SIZE(primes); i++) {
          if ((m % primes[i]) == 0)
            goto next;
        }

        mpz_add_ui(z, z, (mp_limb_t)delta);

        break;
next:
        ;
      }

      if (mpz_bitlen(z) != bits)
        continue;
    }

    if (!mpz_probab_prime_p(z, 20, rng, arg))
      continue;

    break;
  }
}

int
mpz_nextprime(mpz_t z, const mpz_t x, int rounds,
              mp_limb_t max, mp_rng_f *rng, void *arg) {
  mp_limb_t i = 0;

  if (mpz_cmp_ui(x, 2) < 0) {
    mpz_set_ui(z, 2);
    return 1;
  }

  if (max > MP_LIMB_MAX - 2)
    max = MP_LIMB_MAX - 2;

  mpz_set(z, x);

  if (mpz_even_p(z)) {
    mpz_add_ui(z, z, 1);
    i += 1;
  }

  for (; max == 0 || i <= max; i += 2) {
    if (mpz_probab_prime_p(z, rounds, rng, arg))
      return 1;

    mpz_add_ui(z, z, 2);
  }

  return 0;
}

/*
 * Helpers
 */

int
mpz_fits_ui_p(const mpz_t x) {
  return MP_ABS(x->size) <= 1;
}

int
mpz_fits_si_p(const mpz_t x) {
  if (MP_ABS(x->size) > 1)
    return 0;

  if (x->size == 0)
    return 1;

  if (x->size < 0)
    return x->limbs[0] <= MP_LIMB_HI;

  return x->limbs[0] < MP_LIMB_HI;
}

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

static int
mpz_ctz_common(const mpz_t x, const mpz_t y) {
  int u = mpz_ctz(x);
  int v = mpz_ctz(y);
  return MP_MIN(u, v);
}

int
mpz_bitlen(const mpz_t x) {
  return mpn_bitlen(x->limbs, MP_ABS(x->size));
}

size_t
mpz_bytelen(const mpz_t x) {
  return mpn_bytelen(x->limbs, MP_ABS(x->size));
}

size_t
mpz_sizeinbase(const mpz_t x, int base) {
  return mpn_sizeinbase(x->limbs, MP_ABS(x->size), base);
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
 * Limb Helpers
 */

mp_limb_t
mpz_getlimbn(const mpz_t x, int n) {
  if (n >= MP_ABS(x->size))
    return 0;

  return x->limbs[n];
}

int
mpz_size(const mpz_t x) {
  return x->size;
}

const mp_limb_t *
mpz_limbs_read(const mpz_t x) {
  return x->limbs;
}

mp_limb_t *
mpz_limbs_write(mpz_t z, int n) {
  if (z->alloc < n) {
    if (z->alloc > 0)
      mp_free_limbs(z->limbs);

    z->limbs = mp_alloc_limbs(n);
    z->limbs[0] = 0;
    z->alloc = n;
    z->size = 0;
  }

  return z->limbs;
}

mp_limb_t *
mpz_limbs_modify(mpz_t z, int n) {
  mpz_grow(z, n);
  return z->limbs;
}

void
mpz_limbs_finish(mpz_t z, int n) {
  int zn = mpn_strip(z->limbs, MP_ABS(n));

  z->size = n < 0 ? -zn : zn;
}

/*
 * Import
 */

void
mpz_import(mpz_t z, const unsigned char *raw, size_t size, int endian) {
  int zn = mp_cast_size((size + MP_LIMB_BYTES - 1) / MP_LIMB_BYTES);

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
 * String Import
 */

int
mpz_set_str(mpz_t z, const char *str, int base) {
  int neg = 0;
  int zn;

  if (str == NULL) {
    z->size = 0;
    return 0;
  }

  while (mp_isspace(*str))
    str++;

  if (*str == '-') {
    neg = 1;
    str++;
  }

  zn = mp_str_limbs(str, base);

  mpz_grow(z, zn);

  if (!mpn_set_str(z->limbs, zn, str, base)) {
    z->size = 0;
    return 0;
  }

  zn = mpn_strip(z->limbs, zn);

  z->size = neg ? -zn : zn;

  return 1;
}

/*
 * String Export
 */

char *
mpz_get_str(const mpz_t x, int base) {
  size_t len = mpz_sizeinbase(x, base);
  size_t neg = x->size < 0;
  char *str = malloc(neg + len + 1);

  CHECK(str != NULL);

  mpn_get_str(str + neg, x->limbs, MP_ABS(x->size), base);

  if (neg)
    str[0] = '-';

  return str;
}

/*
 * STDIO
 */

void
mpz_print(const mpz_t x, int base, mp_puts_f *mp_puts) {
  char *str = mpz_get_str(x, base);

  mp_puts(str);

  free(str);
}

/*
 * RNG
 */

void
mpz_urandomb(mpz_t z, int bits, mp_rng_f *rng, void *arg) {
  int zn = (bits + MP_LIMB_BITS - 1) / MP_LIMB_BITS;
  int lo = bits % MP_LIMB_BITS;

  mpz_grow(z, zn);

  mpn_random(z->limbs, zn, rng, arg);

  if (lo != 0)
    z->limbs[zn - 1] &= MP_MASK(lo);

  z->size = mpn_strip(z->limbs, zn);

#ifdef TORSION_DEBUG
  ASSERT(mpz_bitlen(z) <= bits);
#endif
}

void
mpz_urandomm(mpz_t z, const mpz_t max, mp_rng_f *rng, void *arg) {
  int bits = mpz_bitlen(max);

  CHECK(z != max);

  if (bits > 0) {
    do {
      mpz_urandomb(z, bits, rng, arg);
    } while (mpz_cmpabs(z, max) >= 0);

    if (mpz_sgn(max) < 0)
      mpz_neg(z, z);
  } else {
    z->size = 0;
  }
}

/*
 * Testing
 */

#if defined(TORSION_DEBUG) && !defined(BUILDING_NODE_EXTENSION)
#  include "../test/mpi_internal.h"
#else
void
test_mpi_internal(mp_rng_f *rng, void *arg) {
  (void)rng;
  (void)arg;
}
#endif
