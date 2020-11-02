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
#include <torsion/common.h>
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
#define mpn_copyi __torsion_mpn_copyi
#define mpn_copyd __torsion_mpn_copyd
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
#define mpn_divmod __torsion_mpn_divmod
#define mpn_div __torsion_mpn_div
#define mpn_mod __torsion_mpn_mod
#define mpn_divround __torsion_mpn_divround
#define mpn_and_n __torsion_mpn_and_n
#define mpn_ior_n __torsion_mpn_ior_n
#define mpn_xor_n __torsion_mpn_xor_n
#define mpn_andn_n __torsion_mpn_andn_n
#define mpn_iorn_n __torsion_mpn_iorn_n
#define mpn_nand_n __torsion_mpn_nand_n
#define mpn_nior_n __torsion_mpn_nior_n
#define mpn_nxor_n __torsion_mpn_nxor_n
#define mpn_com __torsion_mpn_com
#define mpn_lshift __torsion_mpn_lshift
#define mpn_rshift __torsion_mpn_rshift
#define mpn_getbit __torsion_mpn_getbit
#define mpn_getbits __torsion_mpn_getbits
#define mpn_setbit __torsion_mpn_setbit
#define mpn_clrbit __torsion_mpn_clrbit
#define mpn_mask __torsion_mask
#define mpn_neg __torsion_mpn_neg
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
#define mpn_sizeinbase __torsion_mpn_sizeinbase
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
#define mpn_set_str __torsion_mpn_set_str
#define mpn_get_str __torsion_mpn_get_str
#define mpn_print __torsion_mpn_print
#define mpn_random __torsion_mpn_random
#define mpz_init __torsion_mpz_init
#define mpz_init_set __torsion_mpz_init_set
#define mpz_init_set_ui __torsion_mpz_init_set_ui
#define mpz_init_set_si __torsion_mpz_init_set_si
#define mpz_init_set_str __torsion_mpz_init_set_str
#define mpz_clear __torsion_mpz_clear
#define mpz_cleanse __torsion_mpz_cleanse
#define mpz_set __torsion_mpz_set
#define mpz_roset __torsion_mpz_roset
#define mpz_roinit_n __torsion_mpz_roinit_n
#define mpz_set_ui __torsion_mpz_set_ui
#define mpz_set_si __torsion_mpz_set_si
#define mpz_get_ui __torsion_mpz_get_ui
#define mpz_get_si __torsion_mpz_get_si
#define mpz_sgn __torsion_mpz_sgn
#define mpz_cmp __torsion_mpz_cmp
#define mpz_cmp_ui __torsion_mpz_cmp_ui
#define mpz_cmp_si __torsion_mpz_cmp_si
#define mpz_cmpabs __torsion_mpz_cmpabs
#define mpz_cmpabs_ui __torsion_mpz_cmpabs_ui
#define mpz_cmpabs_si __torsion_mpz_cmpabs_si
#define mpz_add __torsion_mpz_add
#define mpz_add_ui __torsion_mpz_add_ui
#define mpz_add_si __torsion_mpz_add_si
#define mpz_sub __torsion_mpz_sub
#define mpz_sub_ui __torsion_mpz_sub_ui
#define mpz_sub_si __torsion_mpz_sub_si
#define mpz_ui_sub __torsion_mpz_ui_sub
#define mpz_si_sub __torsion_mpz_si_sub
#define mpz_mul __torsion_mpz_mul
#define mpz_mul_ui __torsion_mpz_mul_ui
#define mpz_mul_si __torsion_mpz_mul_si
#define mpz_sqr __torsion_mpz_sqr
#define mpz_addmul __torsion_mpz_addmul
#define mpz_addmul_ui __torsion_mpz_addmul_ui
#define mpz_addmul_si __torsion_mpz_addmul_si
#define mpz_submul __torsion_mpz_submul
#define mpz_submul_ui __torsion_mpz_submul_ui
#define mpz_submul_si __torsion_mpz_submul_si
#define mpz_quorem __torsion_mpz_quorem
#define mpz_quo __torsion_mpz_quo
#define mpz_rem __torsion_mpz_rem
#define mpz_quo_ui __torsion_mpz_quo_ui
#define mpz_rem_ui __torsion_mpz_rem_ui
#define mpz_quo_si __torsion_mpz_quo_si
#define mpz_rem_si __torsion_mpz_rem_si
#define mpz_divmod __torsion_mpz_divmod
#define mpz_div __torsion_mpz_div
#define mpz_mod __torsion_mpz_mod
#define mpz_div_ui __torsion_mpz_div_ui
#define mpz_mod_ui __torsion_mpz_mod_ui
#define mpz_div_si __torsion_mpz_div_si
#define mpz_mod_si __torsion_mpz_mod_si
#define mpz_divexact __torsion_mpz_divexact
#define mpz_divexact_ui __torsion_mpz_divexact_ui
#define mpz_divexact_si __torsion_mpz_divexact_si
#define mpz_divisible_p __torsion_mpz_divisible_p
#define mpz_divisible_ui_p __torsion_mpz_divisible_ui_p
#define mpz_divisible_2exp_p __torsion_mpz_divisible_2exp_p
#define mpz_divround __torsion_mpz_divround
#define mpz_pow_ui __torsion_mpz_pow_ui
#define mpz_ui_pow_ui __torsion_mpz_ui_pow_ui
#define mpz_sqrtrem __torsion_mpz_sqrtrem
#define mpz_sqrt __torsion_mpz_sqrt
#define mpz_perfect_square_p __torsion_mpz_perfect_square_p
#define mpz_and __torsion_mpz_and
#define mpz_and_ui __torsion_mpz_and_ui
#define mpz_and_si __torsion_mpz_and_si
#define mpz_ior __torsion_mpz_ior
#define mpz_ior_ui __torsion_mpz_ior_ui
#define mpz_ior_si __torsion_mpz_ior_si
#define mpz_xor __torsion_mpz_xor
#define mpz_xor_ui __torsion_mpz_xor_ui
#define mpz_xor_si __torsion_mpz_xor_si
#define mpz_com __torsion_mpz_com
#define mpz_mul_2exp __torsion_mpz_mul_2exp
#define mpz_quo_2exp __torsion_mpz_quo_2exp
#define mpz_rem_2exp __torsion_mpz_rem_2exp
#define mpz_div_2exp __torsion_mpz_div_2exp
#define mpz_mod_2exp __torsion_mpz_mod_2exp
#define mpz_tstbit __torsion_mpz_tstbit
#define mpz_setbit __torsion_mpz_setbit
#define mpz_clrbit __torsion_mpz_clrbit
#define mpz_combit __torsion_mpz_combit
#define mpz_abs __torsion_mpz_abs
#define mpz_neg __torsion_mpz_neg
#define mpz_gcd __torsion_mpz_gcd
#define mpz_gcd_ui __torsion_mpz_gcd_ui
#define mpz_lcm __torsion_mpz_lcm
#define mpz_lcm_ui __torsion_mpz_lcm_ui
#define mpz_gcdext __torsion_mpz_gcdext
#define mpz_invert __torsion_mpz_invert
#define mpz_jacobi __torsion_mpz_jacobi
#define mpz_powm __torsion_mpz_powm
#define mpz_powm_ui __torsion_mpz_powm_ui
#define mpz_powm_sec __torsion_mpz_powm_sec
#define mpz_sqrtm __torsion_mpz_sqrtm
#define mpz_sqrtp __torsion_mpz_sqrtp
#define mpz_mr_prime_p __torsion_mpz_mr_prime_p
#define mpz_lucas_prime_p __torsion_mpz_lucas_prime_p
#define mpz_probab_prime_p __torsion_mpz_probab_prime_p
#define mpz_randprime __torsion_mpz_randprime
#define mpz_nextprime __torsion_mpz_nextprime
#define mpz_fits_ui_p __torsion_mpz_fits_ui_p
#define mpz_fits_si_p __torsion_mpz_fits_si_p
#define mpz_odd_p __torsion_mpz_odd_p
#define mpz_even_p __torsion_mpz_even_p
#define mpz_ctz __torsion_mpz_ctz
#define mpz_bitlen __torsion_mpz_bitlen
#define mpz_bytelen __torsion_mpz_bytelen
#define mpz_sizeinbase __torsion_mpz_sizeinbase
#define mpz_swap __torsion_mpz_swap
#define mpz_getlimbn __torsion_mpz_getlimbn
#define mpz_size __torsion_mpz_size
#define mpz_limbs_read __torsion_mpz_limbs_read
#define mpz_limbs_write __torsion_mpz_limbs_write
#define mpz_limbs_modify __torsion_mpz_limbs_modify
#define mpz_limbs_finish __torsion_mpz_limbs_finish
#define mpz_import __torsion_mpz_import
#define mpz_export __torsion_mpz_export
#define mpz_set_str __torsion_mpz_set_str
#define mpz_get_str __torsion_mpz_get_str
#define mpz_print __torsion_mpz_print
#define mpz_urandomb __torsion_mpz_urandomb
#define mpz_urandomm __torsion_mpz_urandomm
#define test_mpi_internal __torsion_test_mpi_internal

/*
 * Types
 */

#if defined(TORSION_HAVE_INT128)
typedef int64_t mp_long_t;
typedef uint64_t mp_limb_t;
typedef torsion_uint128_t mp_wide_t;
#  define MP_LIMB_BITS 64
#  define MP_LIMB_BYTES 8
#  define MP_LIMB_C(x) UINT64_C(x)
#  define MP_LIMB_MAX UINT64_MAX
#  define MP_LONG_C(x) INT64_C(x)
#  define MP_LONG_MIN INT64_MIN
#  define MP_LONG_MAX INT64_MAX
#else
typedef int32_t mp_long_t;
typedef uint32_t mp_limb_t;
typedef uint64_t mp_wide_t;
#  define MP_LIMB_BITS 32
#  define MP_LIMB_BYTES 4
#  define MP_LIMB_C(x) UINT32_C(x)
#  define MP_LIMB_MAX UINT32_MAX
#  define MP_LONG_C(x) INT32_C(x)
#  define MP_LONG_MIN INT32_MIN
#  define MP_LONG_MAX INT32_MAX
#endif

#define MP_LIMB_HI (MP_LIMB_C(1) << (MP_LIMB_BITS - 1))
#define MP_MASK(bits) ((MP_LIMB_C(1) << (bits)) - 1)
#define MP_LOW_BITS (MP_LIMB_BITS / 2)
#define MP_LOW_MASK (MP_LIMB_MAX >> MP_LOW_BITS)

TORSION_UNUSED TORSION_BARRIER(mp_limb_t, mp_limb)

struct mpz_s {
  mp_limb_t *limbs;
  int alloc;
  int size;
};

typedef struct mpz_s mpz_t[1];

typedef int mp_puts_f(const char *s);
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
#define MPN_BARRETT_ITCH(shift) ((shift) + 1)
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
 * Macros
 */

#define MPZ_ROINIT_N(xp, xs) {{(mp_limb_t *)(xp), 0, (xs)}}

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
mpn_zero(mp_limb_t *zp, int zn);

/*
 * Uninitialization
 */

void
mpn_cleanse(mp_limb_t *zp, int zn);

/*
 * Assignment
 */

void
mpn_set_1(mp_limb_t *zp, int zn, mp_limb_t x);

void
mpn_copyi(mp_limb_t *zp, const mp_limb_t *xp, int xn);

void
mpn_copyd(mp_limb_t *zp, const mp_limb_t *xp, int xn);

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
 * Round Division
 */

void
mpn_divround(mp_limb_t *qp, const mp_limb_t *np, int nn,
                            const mp_limb_t *dp, int dn);

/*
 * AND
 */

void
mpn_and_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n);

/*
 * OR
 */

void
mpn_ior_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n);

/*
 * XOR
 */

void
mpn_xor_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n);

/*
 * AND+NOT
 */

void
mpn_andn_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n);

/*
 * OR+NOT
 */

void
mpn_iorn_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n);

/*
 * NOT+AND
 */

void
mpn_nand_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n);

/*
 * NOT+OR
 */

void
mpn_nior_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n);

/*
 * NOT+XOR
 */

void
mpn_nxor_n(mp_limb_t *zp, const mp_limb_t *xp, const mp_limb_t *yp, int n);

/*
 * NOT
 */

void
mpn_com(mp_limb_t *zp, const mp_limb_t *xp, int xn);

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
mpn_getbit(const mp_limb_t *xp, int xn, int pos);

mp_limb_t
mpn_getbits(const mp_limb_t *xp, int xn, int pos, int width);

void
mpn_setbit(mp_limb_t *zp, int pos);

void
mpn_clrbit(mp_limb_t *zp, int pos);

void
mpn_mask(mp_limb_t *zp, const mp_limb_t *xp, int xn, int bits);

/*
 * Negation
 */

mp_limb_t
mpn_neg(mp_limb_t *zp, const mp_limb_t *xp, int xn);

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

size_t
mpn_sizeinbase(const mp_limb_t *xp, int xn, int base);

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
 * String Import
 */

int
mpn_set_str(mp_limb_t *zp, int zn, const char *str, int base);

/*
 * String Export
 */

size_t
mpn_get_str(char *str, const mp_limb_t *xp, int xn, int base);

/*
 * STDIO
 */

void
mpn_print(const mp_limb_t *xp, int xn, int base, mp_puts_f *mp_puts);

/*
 * RNG
 */

void
mpn_random(mp_limb_t *zp, int zn, mp_rng_f *rng, void *arg);

/*
 * MPZ Interface
 */

/*
 * Initialization
 */

void
mpz_init(mpz_t z);

void
mpz_init_set(mpz_t z, const mpz_t x);

void
mpz_init_set_ui(mpz_t z, mp_limb_t x);

void
mpz_init_set_si(mpz_t z, mp_long_t x);

int
mpz_init_set_str(mpz_t z, const char *str, int base);

/*
 * Uninitialization
 */

void
mpz_clear(mpz_t z);

void
mpz_cleanse(mpz_t z);

/*
 * Assignment
 */

void
mpz_set(mpz_t z, const mpz_t x);

void
mpz_roset(mpz_t z, const mpz_t x);

void
mpz_roinit_n(mpz_t z, const mp_limb_t *xp, int xs);

void
mpz_set_ui(mpz_t z, mp_limb_t x);

void
mpz_set_si(mpz_t z, mp_long_t x);

/*
 * Conversion
 */

mp_limb_t
mpz_get_ui(const mpz_t x);

mp_long_t
mpz_get_si(const mpz_t x);

/*
 * Comparison
 */

int
mpz_sgn(const mpz_t x);

int
mpz_cmp(const mpz_t x, const mpz_t y);

int
mpz_cmp_ui(const mpz_t x, mp_limb_t y);

int
mpz_cmp_si(const mpz_t x, mp_long_t y);

/*
 * Unsigned Comparison
 */

int
mpz_cmpabs(const mpz_t x, const mpz_t y);

int
mpz_cmpabs_ui(const mpz_t x, mp_limb_t y);

int
mpz_cmpabs_si(const mpz_t x, mp_long_t y);

/*
 * Addition
 */

void
mpz_add(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_add_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_add_si(mpz_t z, const mpz_t x, mp_long_t y);

/*
 * Subtraction
 */

void
mpz_sub(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_sub_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_sub_si(mpz_t z, const mpz_t x, mp_long_t y);

void
mpz_ui_sub(mpz_t z, mp_limb_t x, const mpz_t y);

void
mpz_si_sub(mpz_t z, mp_long_t x, const mpz_t y);

/*
 * Multiplication
 */

void
mpz_mul(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_mul_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_mul_si(mpz_t z, const mpz_t x, mp_long_t y);

void
mpz_sqr(mpz_t z, const mpz_t x);

void
mpz_addmul(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_addmul_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_addmul_si(mpz_t z, const mpz_t x, mp_long_t y);

void
mpz_submul(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_submul_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_submul_si(mpz_t z, const mpz_t x, mp_long_t y);

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

mp_long_t
mpz_quo_si(mpz_t q, const mpz_t n, mp_long_t d);

mp_long_t
mpz_rem_si(const mpz_t n, mp_long_t d);

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

mp_long_t
mpz_div_si(mpz_t q, const mpz_t n, mp_long_t d);

mp_long_t
mpz_mod_si(const mpz_t n, mp_long_t d);

/*
 * Exact Division
 */

void
mpz_divexact(mpz_t q, const mpz_t n, const mpz_t d);

void
mpz_divexact_ui(mpz_t q, const mpz_t n, mp_limb_t d);

void
mpz_divexact_si(mpz_t q, const mpz_t n, mp_long_t d);

/*
 * Divisibility
 */

int
mpz_divisible_p(const mpz_t n, const mpz_t d);

int
mpz_divisible_ui_p(const mpz_t n, mp_limb_t d);

int
mpz_divisible_2exp_p(const mpz_t n, int bits);

/*
 * Round Division
 */

void
mpz_divround(mpz_t q, const mpz_t n, const mpz_t d);

/*
 * Exponentiation
 */

void
mpz_pow_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_ui_pow_ui(mpz_t z, mp_limb_t x, mp_limb_t y);

/*
 * Roots
 */

void
mpz_sqrtrem(mpz_t z, mpz_t r, const mpz_t x);

void
mpz_sqrt(mpz_t z, const mpz_t x);

int
mpz_perfect_square_p(const mpz_t x);

/*
 * AND
 */

void
mpz_and(mpz_t z, const mpz_t x, const mpz_t y);

mp_limb_t
mpz_and_ui(const mpz_t x, mp_limb_t y);

void
mpz_and_si(mpz_t z, const mpz_t x, mp_long_t y);

/*
 * OR
 */

void
mpz_ior(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_ior_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_ior_si(mpz_t z, const mpz_t x, mp_long_t y);

/*
 * XOR
 */

void
mpz_xor(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_xor_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_xor_si(mpz_t z, const mpz_t x, mp_long_t y);

/*
 * NOT
 */

void
mpz_com(mpz_t z, const mpz_t x);

/*
 * Left Shift
 */

void
mpz_mul_2exp(mpz_t z, const mpz_t x, int bits);

/*
 * Unsigned Right Shift
 */

void
mpz_quo_2exp(mpz_t z, const mpz_t x, int bits);

void
mpz_rem_2exp(mpz_t z, const mpz_t x, int bits);

/*
 * Right Shift
 */

void
mpz_div_2exp(mpz_t z, const mpz_t x, int bits);

void
mpz_mod_2exp(mpz_t z, const mpz_t x, int bits);

/*
 * Bit Manipulation
 */

int
mpz_tstbit(const mpz_t x, int pos);

void
mpz_setbit(mpz_t z, int pos);

void
mpz_clrbit(mpz_t z, int pos);

void
mpz_combit(mpz_t z, int pos);

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

mp_limb_t
mpz_gcd_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_lcm(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_lcm_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_gcdext(mpz_t g, mpz_t s, mpz_t t, const mpz_t x, const mpz_t y);

int
mpz_invert(mpz_t z, const mpz_t x, const mpz_t y);

int
mpz_jacobi(const mpz_t x, const mpz_t y);

void
mpz_powm(mpz_t z, const mpz_t x, const mpz_t y, const mpz_t m);

void
mpz_powm_ui(mpz_t z, const mpz_t x, mp_limb_t y, const mpz_t m);

void
mpz_powm_sec(mpz_t z, const mpz_t x, const mpz_t y, const mpz_t m);

int
mpz_sqrtm(mpz_t z, const mpz_t u, const mpz_t p);

int
mpz_sqrtpq(mpz_t z, const mpz_t x, const mpz_t p, const mpz_t q);

/*
 * Primality Testing
 */

int
mpz_mr_prime_p(const mpz_t n, int reps, int force2, mp_rng_f *rng, void *arg);

int
mpz_lucas_prime_p(const mpz_t n, mp_limb_t limit);

int
mpz_probab_prime_p(const mpz_t x, int rounds, mp_rng_f *rng, void *arg);

void
mpz_randprime(mpz_t z, int bits, mp_rng_f *rng, void *arg);

int
mpz_nextprime(mpz_t z, const mpz_t x, int rounds,
              mp_limb_t max, mp_rng_f *rng, void *arg);

/*
 * Helpers
 */

int
mpz_fits_ui_p(const mpz_t x);

int
mpz_fits_si_p(const mpz_t x);

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

size_t
mpz_sizeinbase(const mpz_t x, int base);

void
mpz_swap(mpz_t x, mpz_t y);

/*
 * Limb Helpers
 */

mp_limb_t
mpz_getlimbn(const mpz_t x, int n);

int
mpz_size(const mpz_t x);

const mp_limb_t *
mpz_limbs_read(const mpz_t x);

mp_limb_t *
mpz_limbs_write(mpz_t z, int n);

mp_limb_t *
mpz_limbs_modify(mpz_t z, int n);

void
mpz_limbs_finish(mpz_t z, int n);

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
 * String Import
 */

int
mpz_set_str(mpz_t z, const char *str, int base);

/*
 * String Export
 */

char *
mpz_get_str(const mpz_t x, int base);

/*
 * STDIO
 */

void
mpz_print(const mpz_t x, int base, mp_puts_f *mp_puts);

/*
 * RNG
 */

void
mpz_urandomb(mpz_t z, int bits, mp_rng_f *rng, void *arg);

void
mpz_urandomm(mpz_t z, const mpz_t max, mp_rng_f *rng, void *arg);

/*
 * Testing
 */

TORSION_EXTERN void
test_mpi_internal(mp_rng_f *rng, void *arg);

#endif /* _TORSION_MPI_H */
