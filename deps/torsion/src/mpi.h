/*!
 * mpi.h - multi-precision integers for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * A from-scratch reimplementation of GMP.
 */

#ifndef _TORSION_MPI_H
#define _TORSION_MPI_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include "internal.h"

/*
 * Symbol Aliases
 */

#define mp_alloc_limbs __torsion_mp_alloc_limbs
#define mp_realloc_limbs __torsion_mp_realloc_limbs
#define mp_free_limbs __torsion_mp_free_limbs
#define mpn_zero __torsion_mpn_zero
#define mpn_cleanse __torsion_mpn_cleanse
#define mpn_set_1 __torsion_mpn_set_1
#define mpn_copy __torsion_mpn_copy
#define mpn_zero_p __torsion_mpn_zero_p
#define mpn_cmp __torsion_mpn_cmp
#define mpn_add_1 __torsion_mpn_add_1
#define mpn_add_n __torsion_mpn_add_n
#define mpn_add __torsion_mpn_add
#define mpn_sub_1 __torsion_mpn_sub_1
#define mpn_sub_n __torsion_mpn_sub_n
#define mpn_sub __torsion_mpn_sub
#define mpn_mul_1 __torsion_mpn_mul_1
#define mpn_addmul_1 __torsion_mpn_addmul_1
#define mpn_submul_1 __torsion_mpn_submul_1
#define mpn_mul_n __torsion_mpn_mul_n
#define mpn_mul __torsion_mpn_mul
#define mpn_sqr __torsion_mpn_sqr
#define mpn_mulshift __torsion_mpn_mulshift
#define mpn_reduce_weak __torsion_mpn_reduce_weak
#define mpn_barrett __torsion_mpn_barrett
#define mpn_reduce __torsion_mpn_reduce
#define mpn_mont __torsion_mpn_mont
#define mpn_montmul __torsion_mpn_montmul
#define mpn_montmul_var __torsion_mpn_montmul_var
#define mpn_divmod_1 __torsion_mpn_divmod_1
#define mpn_div_1 __torsion_mpn_div_1
#define mpn_mod_1 __torsion_mpn_mod_1
#define mpn_mod_2 __torsion_mpn_mod_2
#define mpn_divmod __torsion_mpn_divmod
#define mpn_div __torsion_mpn_div
#define mpn_mod __torsion_mpn_mod
#define mpn_lshift __torsion_mpn_lshift
#define mpn_rshift __torsion_mpn_rshift
#define mpn_get_bit __torsion_mpn_get_bit
#define mpn_get_bits __torsion_mpn_get_bits
#define mpn_invert __torsion_mpn_invert
#define mpn_invert_n __torsion_mpn_invert_n
#define mpn_jacobi __torsion_mpn_jacobi
#define mpn_jacobi_n __torsion_mpn_jacobi_n
#define mpn_powm __torsion_mpn_powm
#define mpn_sec_powm __torsion_mpn_sec_powm
#define mpn_strip __torsion_mpn_strip
#define mpn_odd_p __torsion_mpn_odd_p
#define mpn_even_p __torsion_mpn_even_p
#define mpn_ctz __torsion_mpn_ctz
#define mpn_bitlen __torsion_mpn_bitlen
#define mpn_bytelen __torsion_mpn_bytelen
#define mpn_swap __torsion_mpn_swap
#define mpn_select __torsion_mpn_select
#define mpn_select_zero __torsion_mpn_select_zero
#define mpn_sec_zero_p __torsion_mpn_sec_zero_p
#define mpn_sec_equal __torsion_mpn_sec_equal
#define mpn_sec_cmp __torsion_mpn_sec_cmp
#define mpn_sec_lt __torsion_mpn_sec_lt
#define mpn_sec_lte __torsion_mpn_sec_lte
#define mpn_sec_gt __torsion_mpn_sec_gt
#define mpn_sec_gte __torsion_mpn_sec_gte
#define mpn_import __torsion_mpn_import
#define mpn_export __torsion_mpn_export
#define mpz_init __torsion_mpz_init
#define mpz_clear __torsion_mpz_clear
#define mpz_cleanse __torsion_mpz_cleanse
#define mpz_set __torsion_mpz_set
#define mpz_roset __torsion_mpz_roset
#define mpz_set_ui __torsion_mpz_set_ui
#define mpz_set_u64 __torsion_mpz_set_u64
#define mpz_get_ui __torsion_mpz_get_ui
#define mpz_get_u64 __torsion_mpz_get_u64
#define mpz_sgn __torsion_mpz_sgn
#define mpz_cmp __torsion_mpz_cmp
#define mpz_cmp_ui __torsion_mpz_cmp_ui
#define mpz_cmpabs __torsion_mpz_cmpabs
#define mpz_cmpabs_ui __torsion_mpz_cmpabs_ui
#define mpz_add __torsion_mpz_add
#define mpz_add_ui __torsion_mpz_add_ui
#define mpz_sub __torsion_mpz_sub
#define mpz_sub_ui __torsion_mpz_sub_ui
#define mpz_mul __torsion_mpz_mul
#define mpz_mul_ui __torsion_mpz_mul_ui
#define mpz_sqr __torsion_mpz_sqr
#define mpz_quorem __torsion_mpz_quorem
#define mpz_quo __torsion_mpz_quo
#define mpz_rem __torsion_mpz_rem
#define mpz_quo_ui __torsion_mpz_quo_ui
#define mpz_rem_ui __torsion_mpz_rem_ui
#define mpz_divmod __torsion_mpz_divmod
#define mpz_div __torsion_mpz_div
#define mpz_mod __torsion_mpz_mod
#define mpz_div_ui __torsion_mpz_div_ui
#define mpz_mod_ui __torsion_mpz_mod_ui
#define mpz_divexact __torsion_mpz_divexact
#define mpz_divexact_ui __torsion_mpz_divexact_ui
#define mpz_lshift __torsion_mpz_lshift
#define mpz_rshift __torsion_mpz_rshift
#define mpz_get_bit __torsion_mpz_get_bit
#define mpz_get_bits __torsion_mpz_get_bits
#define mpz_set_bit __torsion_mpz_set_bit
#define mpz_clr_bit __torsion_mpz_clr_bit
#define mpz_abs __torsion_mpz_abs
#define mpz_neg __torsion_mpz_neg
#define mpz_gcd __torsion_mpz_gcd
#define mpz_lcm __torsion_mpz_lcm
#define mpz_gcdext __torsion_mpz_gcdext
#define mpz_invert __torsion_mpz_invert
#define mpz_jacobi __torsion_mpz_jacobi
#define mpz_powm __torsion_mpz_powm
#define mpz_powm_sec __torsion_mpz_powm_sec
#define mpz_is_prime_mr __torsion_mpz_is_prime_mr
#define mpz_is_prime_lucas __torsion_mpz_is_prime_lucas
#define mpz_is_prime __torsion_mpz_is_prime
#define mpz_random_prime __torsion_mpz_random_prime
#define mpz_odd_p __torsion_mpz_odd_p
#define mpz_even_p __torsion_mpz_even_p
#define mpz_ctz __torsion_mpz_ctz
#define mpz_bitlen __torsion_mpz_bitlen
#define mpz_bytelen __torsion_mpz_bytelen
#define mpz_swap __torsion_mpz_swap
#define mpz_import __torsion_mpz_import
#define mpz_export __torsion_mpz_export
#define mpz_random_bits __torsion_mpz_random_bits
#define mpz_random_int __torsion_mpz_random_int

/*
 * Types
 */

#if defined(TORSION_HAVE_INT128)
typedef uint64_t mp_limb_t;
typedef torsion_uint128_t mp_wide_t;
#  define MP_LIMB_BITS 64
#  define MP_LIMB_BYTES 8
#  define MP_LIMB_C(x) UINT64_C(x)
#  define MP_LIMB_MAX MP_LIMB_C(0xffffffffffffffff)
#else
typedef uint32_t mp_limb_t;
typedef uint64_t mp_wide_t;
#  define MP_LIMB_BITS 32
#  define MP_LIMB_BYTES 4
#  define MP_LIMB_C(x) UINT32_C(x)
#  define MP_LIMB_MAX MP_LIMB_C(0xffffffff)
#endif

#define MP_LOW_BITS (MP_LIMB_BITS / 2)
#define MP_LOW_MASK (MP_LIMB_MAX >> MP_LOW_BITS)
#define MP_SIZE_MAX (INT_MAX / MP_LIMB_BITS)

TORSION_BARRIER(mp_limb_t, mp_limb)

struct mpz_s {
  mp_limb_t *limbs;
  int alloc;
  int size;
};

typedef struct mpz_s mpz_t[1];

typedef void mp_rng_f(void *out, size_t size, void *arg);

/*
 * Definitions
 */

#define MP_SLIDE_WIDTH 4
#define MP_SLIDE_SIZE (1 << (MP_SLIDE_WIDTH - 1))
#define MP_FIXED_WIDTH 4
#define MP_FIXED_SIZE (1 << MP_FIXED_WIDTH)

/*
 * Itches
 */

#define MPN_SQR_ITCH(n) (2 * (n))
#define MPN_MULSHIFT_ITCH(n) (2 * (n))
#define MPN_REDUCE_WEAK_ITCH(n) (n)
#define MPN_BARRETT_ITCH(n, shift) ((shift) + 1 - (n) + 1)
#define MPN_REDUCE_ITCH(n, shift) (1 + (shift) + ((shift) - (n) + 1))
#define MPN_MONT_ITCH(n) (2 * (n) + 1)
#define MPN_MONTMUL_ITCH(n) (2 * (n))
#define MPN_INVERT_ITCH(n) (4 * ((n) + 1))
#define MPN_JACOBI_ITCH(n) (2 * (n))
#define MPN_SLIDE_ITCH(yn, mn) ((yn) > 2 ? (MP_SLIDE_SIZE * (mn)) : 0)
#define MPN_POWM_ITCH(yn, mn) (6 * (mn) + MPN_SLIDE_ITCH(yn, mn))
#define MPN_SEC_POWM_ITCH(n) (5 * (n) + MP_FIXED_SIZE * (n) + 1)

/* Either Barrett or Montgomery precomputation. */
#define MPN_BARRETT_MONT_ITCH(shift) ((shift) + 2)

/*
 * Allocation
 */

mp_limb_t *
mp_alloc_limbs(int size);

mp_limb_t *
mp_realloc_limbs(mp_limb_t *ptr, int size);

void
mp_free_limbs(mp_limb_t *ptr);

/*
 * MPN Interface
 */

/*
 * Initialization
 */

void
mpn_zero(mp_limb_t *xp, int xn);

/*
 * Uninitialization
 */

void
mpn_cleanse(mp_limb_t *xp, int xn);

/*
 * Assignment
 */

void
mpn_set_1(mp_limb_t *xp, int xn, mp_limb_t y);

void
mpn_copy(mp_limb_t *zp, const mp_limb_t *xp, int xn);

/*
 * Comparison
 */

int
mpn_zero_p(const mp_limb_t *xp, int xn);

int
mpn_cmp(const mp_limb_t *xp, const mp_limb_t *yp, int n);

/*
 * Addition
 */

mp_limb_t
mpn_add_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y);

mp_limb_t
mpn_add_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n);

mp_limb_t
mpn_add(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                       const mp_limb_t *yp, int yn);

/*
 * Subtraction
 */

mp_limb_t
mpn_sub_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y);

mp_limb_t
mpn_sub_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n);

mp_limb_t
mpn_sub(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                       const mp_limb_t *yp, int yn);

/*
 * Multiplication
 */

mp_limb_t
mpn_mul_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y);

mp_limb_t
mpn_addmul_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y);

mp_limb_t
mpn_submul_1(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t y);

void
mpn_mul_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n);

void
mpn_mul(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                       const mp_limb_t *yp, int yn);

void
mpn_sqr(mp_limb_t *zp, const mp_limb_t *xp, int xn, mp_limb_t *scratch);

/*
 * Multiply + Shift
 */

mp_limb_t
mpn_mulshift(mp_limb_t *zp,
             const mp_limb_t *xp,
             const mp_limb_t *yp,
             int n, int bits,
             mp_limb_t *scratch);

/*
 * Weak Reduction
 */

int
mpn_reduce_weak(mp_limb_t *zp,
                const mp_limb_t *xp,
                const mp_limb_t *np,
                int n, mp_limb_t hi,
                mp_limb_t *scratch);

/*
 * Barrett Reduction
 */

void
mpn_barrett(mp_limb_t *mp, const mp_limb_t *np,
            int n, int shift, mp_limb_t *scratch);

void
mpn_reduce(mp_limb_t *zp, const mp_limb_t *xp,
                          const mp_limb_t *mp,
                          const mp_limb_t *np,
                          int n, int shift,
                          mp_limb_t *scratch);

/*
 * Montgomery Multiplication
 */

void
mpn_mont(mp_limb_t *kp, mp_limb_t *rp,
         const mp_limb_t *mp, int n,
         mp_limb_t *scratch);

void
mpn_montmul(mp_limb_t *zp,
            const mp_limb_t *xp,
            const mp_limb_t *yp,
            const mp_limb_t *mp,
            int n, mp_limb_t k,
            mp_limb_t *scratch);

void
mpn_montmul_var(mp_limb_t *zp,
                const mp_limb_t *xp,
                const mp_limb_t *yp,
                const mp_limb_t *mp,
                int n, mp_limb_t k,
                mp_limb_t *scratch);

/*
 * Division
 */

mp_limb_t
mpn_divmod_1(mp_limb_t *qp, const mp_limb_t *np, int nn, mp_limb_t d);

void
mpn_div_1(mp_limb_t *qp, const mp_limb_t *np, int nn, mp_limb_t d);

mp_limb_t
mpn_mod_1(const mp_limb_t *np, int nn, mp_limb_t d);

mp_wide_t
mpn_mod_2(const mp_limb_t *np, int nn, mp_wide_t d);

void
mpn_divmod(mp_limb_t *qp, mp_limb_t *rp,
           const mp_limb_t *np, int nn,
           const mp_limb_t *dp, int dn);

void
mpn_div(mp_limb_t *qp, const mp_limb_t *np, int nn,
                       const mp_limb_t *dp, int dn);

void
mpn_mod(mp_limb_t *rp, const mp_limb_t *np, int nn,
                       const mp_limb_t *dp, int dn);

/*
 * Left Shift
 */

mp_limb_t
mpn_lshift(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits);

/*
 * Right Shift
 */

mp_limb_t
mpn_rshift(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits);

/*
 * Bit Manipulation
 */

mp_limb_t
mpn_get_bit(const mp_limb_t *xp, int xn, int pos);

mp_limb_t
mpn_get_bits(const mp_limb_t *xp, int xn, int pos, int width);

/*
 * Number Theoretic Functions
 */

int
mpn_invert(mp_limb_t *zp,
           const mp_limb_t *xp, int xn,
           const mp_limb_t *yp, int yn,
           mp_limb_t *scratch);

int
mpn_invert_n(mp_limb_t *zp,
             const mp_limb_t *xp,
             const mp_limb_t *yp,
             int n,
             mp_limb_t *scratch);

int
mpn_jacobi(const mp_limb_t *xp, int xn,
           const mp_limb_t *yp, int yn,
           mp_limb_t *scratch);

int
mpn_jacobi_n(const mp_limb_t *xp,
             const mp_limb_t *yp,
             int n,
             mp_limb_t *scratch);

void
mpn_powm(mp_limb_t *zp, const mp_limb_t *xp, int xn,
                        const mp_limb_t *yp, int yn,
                        const mp_limb_t *mp, int mn,
                        mp_limb_t *scratch);

void
mpn_sec_powm(mp_limb_t *zp,
             const mp_limb_t *xp, int xn,
             const mp_limb_t *yp, int yn,
             const mp_limb_t *mp, int mn,
             mp_limb_t *scratch);

/*
 * Helpers
 */

int
mpn_strip(const mp_limb_t *xp, int xn);

int
mpn_odd_p(const mp_limb_t *xp, int xn);

int
mpn_even_p(const mp_limb_t *xp, int xn);

int
mpn_ctz(const mp_limb_t *xp, int xn);

int
mpn_bitlen(const mp_limb_t *xp, int xn);

size_t
mpn_bytelen(const mp_limb_t *xp, int xn);

void
mpn_swap(mp_limb_t **xp, int *xn,
         mp_limb_t **yp, int *yn);

/*
 * Constant Time
 */

void
mpn_select(mp_limb_t *zp,
           const mp_limb_t *xp,
           const mp_limb_t *yp,
           int n, int flag);

void
mpn_select_zero(mp_limb_t *zp, const mp_limb_t *xp, int n, int flag);

int
mpn_sec_zero_p(const mp_limb_t *xp, int xn);

int
mpn_sec_equal(const mp_limb_t *xp, const mp_limb_t *yp, int n);

int
mpn_sec_cmp(const mp_limb_t *xp, const mp_limb_t *yp, int n);

int
mpn_sec_lt(const mp_limb_t *xp, const mp_limb_t *yp, int n);

int
mpn_sec_lte(const mp_limb_t *xp, const mp_limb_t *yp, int n);

int
mpn_sec_gt(const mp_limb_t *xp, const mp_limb_t *yp, int n);

int
mpn_sec_gte(const mp_limb_t *xp, const mp_limb_t *yp, int n);

/*
 * Import
 */

void
mpn_import(mp_limb_t *zp, int zn,
           const unsigned char *raw,
           size_t len, int endian);

/*
 * Export
 */

void
mpn_export(unsigned char *raw, size_t len,
           const mp_limb_t *xp, int xn, int endian);

/*
 * MPZ Interface
 */

/*
 * Initialization
 */

void
mpz_init(mpz_t x);

/*
 * Uninitialization
 */

void
mpz_clear(mpz_t x);

void
mpz_cleanse(mpz_t x);

/*
 * Assignment
 */

void
mpz_set(mpz_t z, const mpz_t x);

void
mpz_roset(mpz_t z, const mpz_t x);

void
mpz_set_ui(mpz_t z, mp_limb_t x);

void
mpz_set_u64(mpz_t z, uint64_t x);

/*
 * Conversion
 */

mp_limb_t
mpz_get_ui(const mpz_t x);

uint64_t
mpz_get_u64(const mpz_t x);

/*
 * Comparison
 */

int
mpz_sgn(const mpz_t x);

int
mpz_cmp(const mpz_t x, const mpz_t y);

int
mpz_cmp_ui(const mpz_t x, mp_limb_t y);

/*
 * Unsigned Comparison
 */

int
mpz_cmpabs(const mpz_t x, const mpz_t y);

int
mpz_cmpabs_ui(const mpz_t x, mp_limb_t y);

/*
 * Addition
 */

void
mpz_add(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_add_ui(mpz_t z, const mpz_t x, mp_limb_t y);

/*
 * Subtraction
 */

void
mpz_sub(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_sub_ui(mpz_t z, const mpz_t x, mp_limb_t y);

/*
 * Multiplication
 */

void
mpz_mul(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_mul_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_sqr(mpz_t z, const mpz_t x);

/*
 * Truncation Division
 */

void
mpz_quorem(mpz_t q, mpz_t r, const mpz_t n, const mpz_t d);

void
mpz_quo(mpz_t q, const mpz_t n, const mpz_t d);

void
mpz_rem(mpz_t r, const mpz_t n, const mpz_t d);

mp_limb_t
mpz_quo_ui(mpz_t q, const mpz_t n, mp_limb_t d);

mp_limb_t
mpz_rem_ui(const mpz_t n, mp_limb_t d);

/*
 * Euclidean Division
 */

void
mpz_divmod(mpz_t q, mpz_t r, const mpz_t n, const mpz_t d);

void
mpz_div(mpz_t q, const mpz_t n, const mpz_t d);

void
mpz_mod(mpz_t r, const mpz_t n, const mpz_t d);

mp_limb_t
mpz_div_ui(mpz_t q, const mpz_t n, mp_limb_t d);

mp_limb_t
mpz_mod_ui(const mpz_t n, mp_limb_t d);

/*
 * Exact Division
 */

void
mpz_divexact(mpz_t q, const mpz_t n, const mpz_t d);

void
mpz_divexact_ui(mpz_t q, const mpz_t n, mp_limb_t d);

/*
 * Left Shift
 */

void
mpz_lshift(mpz_t z, const mpz_t x, int bits);

/*
 * Right Shift
 */

void
mpz_rshift(mpz_t z, const mpz_t x, int bits);

/*
 * Bit Manipulation
 */

mp_limb_t
mpz_get_bit(const mpz_t x, int pos);

mp_limb_t
mpz_get_bits(const mpz_t x, int pos, int width);

void
mpz_set_bit(mpz_t x, int pos);

void
mpz_clr_bit(mpz_t x, int pos);

/*
 * Negation
 */

void
mpz_abs(mpz_t z, const mpz_t x);

void
mpz_neg(mpz_t z, const mpz_t x);

/*
 * Number Theoretic Functions
 */

void
mpz_gcd(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_lcm(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_gcdext(mpz_t g, mpz_t s, mpz_t t, const mpz_t x, const mpz_t y);

int
mpz_invert(mpz_t z, const mpz_t x, const mpz_t y);

int
mpz_jacobi(const mpz_t x, const mpz_t y);

void
mpz_powm(mpz_t z, const mpz_t x, const mpz_t y, const mpz_t m);

void
mpz_powm_sec(mpz_t z, const mpz_t x, const mpz_t y, const mpz_t m);

/*
 * Primality Testing
 */

int
mpz_is_prime_mr(const mpz_t n, int reps, int force2, mp_rng_f *rng, void *arg);

int
mpz_is_prime_lucas(const mpz_t n, mp_limb_t limit);

int
mpz_is_prime(const mpz_t n, int rounds, mp_rng_f *rng, void *arg);

void
mpz_random_prime(mpz_t z, int bits, mp_rng_f *rng, void *arg);

/*
 * Helpers
 */

int
mpz_odd_p(const mpz_t x);

int
mpz_even_p(const mpz_t x);

int
mpz_ctz(const mpz_t x);

int
mpz_bitlen(const mpz_t x);

size_t
mpz_bytelen(const mpz_t x);

void
mpz_swap(mpz_t x, mpz_t y);

/*
 * Import
 */

void
mpz_import(mpz_t z, const unsigned char *raw, size_t size, int endian);

/*
 * Export
 */

void
mpz_export(unsigned char *raw, const mpz_t x, size_t size, int endian);

/*
 * RNG
 */

void
mpz_random_bits(mpz_t z, int bits, mp_rng_f *rng, void *arg);

void
mpz_random_int(mpz_t z, const mpz_t max, mp_rng_f *rng, void *arg);

#endif /* _TORSION_MPI_H */
