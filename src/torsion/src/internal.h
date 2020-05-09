/*!
 * internal.h - internal utils for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Several macros based on GMP and libsecp256k1.
 */

#ifndef _TORSION_INTERNAL_H
#define _TORSION_INTERNAL_H

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define TORSION_GNUC_PREREQ(maj, min) \
  ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
#define TORSION_GNUC_PREREQ(maj, min) 0
#endif

#if TORSION_GNUC_PREREQ(3, 0) || __has_builtin(__builtin_expect)
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define LIKELY(x) (x)
#define UNLIKELY(x) (x)
#endif

#ifdef TORSION_NO_ASSERT
#define ASSERT(expr) (void)(expr)
#else
#define ASSERT(expr) do {                             \
  if (UNLIKELY(!(expr)))                              \
    __torsion_assert_fail(__FILE__, __LINE__, #expr); \
} while (0)
#endif

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
#  if TORSION_GNUC_PREREQ(2, 7)
#    define TORSION_INLINE __inline__
#  elif defined(_MSC_VER)
#    define TORSION_INLINE __inline
#  else
#    define TORSION_INLINE
#  endif
#else
#  define TORSION_INLINE inline
#endif

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
#  if TORSION_GNUC_PREREQ(3, 0)
#    define TORSION_RESTRICT __restrict__
#  elif defined(_MSC_VER) && _MSC_VER >= 1400
#    define TORSION_RESTRICT __restrict
#  else
#    define TORSION_RESTRICT
#  endif
#else
#  define TORSION_RESTRICT restrict
#endif

#if defined(__GNUC__) || defined(__clang__)
#define TORSION_UNUSED __attribute__((unused))
#else
#define TORSION_UNUSED
#endif

#ifdef __GNUC__
#define TORSION_EXTENSION __extension__
#else
#define TORSION_EXTENSION
#endif

#if defined(TORSION_USE_64BIT)
#if defined(__SIZEOF_INT128__) || defined(TORSION_HAS_INT128)
TORSION_EXTENSION typedef unsigned __int128 torsion_uint128_t;
TORSION_EXTENSION typedef signed __int128 torsion_int128_t;
#ifndef TORSION_HAS_INT128
#define TORSION_HAS_INT128
#endif
#elif defined(__GNUC__)
typedef unsigned torsion_uint128_t __attribute__((mode(TI)));
typedef signed torsion_int128_t __attribute__((mode(TI)));
#define TORSION_HAS_INT128
#endif
#endif

#if defined(TORSION_HAS_INT128) && !defined(TORSION_USE_64BIT)
#error "Cannot define TORSION_HAS_INT128 without TORSION_USE_64BIT."
#endif

#if defined(TORSION_USE_ASM) && !defined(TORSION_USE_64BIT)
#error "Cannot define TORSION_USE_ASM without TORSION_USE_64BIT."
#endif

#if (-1 & 3) != 3
#error "Two's complement is required."
#endif

#define ENTROPY_SIZE 32

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#ifndef TORSION_NO_ASSERT
void
__torsion_assert_fail(const char *file, int line, const char *expr);
#endif

#define torsion_die __torsion_die

void
torsion_die(const char *msg);

#endif /* _TORSION_INTERNAL_H */
