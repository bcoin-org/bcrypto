/*!
 * mini-gmp, a minimalistic implementation of a GNU GMP subset.
 *
 * Copyright 2011-2015, 2017, 2019 Free Software Foundation, Inc.
 *
 * This file is part of the GNU MP Library.
 *
 * The GNU MP Library is free software; you can redistribute it and/or modify
 * it under the terms of either:
 *
 *   * the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at your
 *     option) any later version.
 *
 * or
 *
 *   * the GNU General Public License as published by the Free Software
 *     Foundation; either version 2 of the License, or (at your option) any
 *     later version.
 *
 * or both in parallel, as here.
 *
 * The GNU MP Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received copies of the GNU General Public License and the
 * GNU Lesser General Public License along with the GNU MP Library.  If not,
 * see https://www.gnu.org/licenses/.  */

/* About mini-gmp: This is a minimal implementation of a subset of the
 * GMP interface. It is intended for inclusion into applications which
 * have modest bignums needs, as a fallback when the real GMP library
 * is not installed.
 *
 * This file defines the public interface.
 */

#ifndef __MINI_GMP_H__
#define __MINI_GMP_H__

#define MINI_GMP_FIXED_LIMBS

/* For size_t */
#include <stddef.h>

#ifdef MINI_GMP_FIXED_LIMBS
/* For uint(32,64}_t */
#include <stdint.h>
#else
/* For CHAR_BIT */
#include <limits.h>
#endif

#ifdef __GNUC__
#define MINI_GMP_EXTENSION __extension__
#else
#define MINI_GMP_EXTENSION
#endif

#if defined(__cplusplus)
extern "C" {
#endif

/* Alias */
#define mp_set_memory_functions _torsion_mp_set_memory_functions
#define mp_get_memory_functions _torsion_mp_get_memory_functions
#define mp_bits_per_limb _torsion_mp_bits_per_limb
#define mpn_copyi _torsion_mpn_copyi
#define mpn_copyd _torsion_mpn_copyd
#define mpn_zero _torsion_mpn_zero
#define mpn_cmp _torsion_mpn_cmp
#define mpn_zero_p _torsion_mpn_zero_p
#define mpn_add_1 _torsion_mpn_add_1
#define mpn_add_n _torsion_mpn_add_n
#define mpn_add _torsion_mpn_add
#define mpn_sub_1 _torsion_mpn_sub_1
#define mpn_sub_n _torsion_mpn_sub_n
#define mpn_sub _torsion_mpn_sub
#define mpn_mul_1 _torsion_mpn_mul_1
#define mpn_addmul_1 _torsion_mpn_addmul_1
#define mpn_submul_1 _torsion_mpn_submul_1
#define mpn_mul _torsion_mpn_mul
#define mpn_mul_n _torsion_mpn_mul_n
#define mpn_sqr _torsion_mpn_sqr
#define mpn_perfect_square_p _torsion_mpn_perfect_square_p
#define mpn_sqrtrem _torsion_mpn_sqrtrem
#define mpn_lshift _torsion_mpn_lshift
#define mpn_rshift _torsion_mpn_rshift
#define mpn_scan0 _torsion_mpn_scan0
#define mpn_scan1 _torsion_mpn_scan1
#define mpn_com _torsion_mpn_com
#define mpn_neg _torsion_mpn_neg
#define mpn_popcount _torsion_mpn_popcount
#define mpn_invert_3by2 _torsion_mpn_invert_3by2
#define mpn_tdiv_qr _torsion_mpn_tdiv_qr
#define mpn_get_str _torsion_mpn_get_str
#define mpn_set_str _torsion_mpn_set_str
#define mpz_init _torsion_mpz_init
#define mpz_init2 _torsion_mpz_init2
#define mpz_clear _torsion_mpz_clear
#define mpz_sgn _torsion_mpz_sgn
#define mpz_cmp_si _torsion_mpz_cmp_si
#define mpz_cmp_ui _torsion_mpz_cmp_ui
#define mpz_cmp _torsion_mpz_cmp
#define mpz_cmpabs_ui _torsion_mpz_cmpabs_ui
#define mpz_cmpabs _torsion_mpz_cmpabs
#define mpz_cmp_d _torsion_mpz_cmp_d
#define mpz_cmpabs_d _torsion_mpz_cmpabs_d
#define mpz_abs _torsion_mpz_abs
#define mpz_neg _torsion_mpz_neg
#define mpz_swap _torsion_mpz_swap
#define mpz_add_ui _torsion_mpz_add_ui
#define mpz_add _torsion_mpz_add
#define mpz_sub_ui _torsion_mpz_sub_ui
#define mpz_ui_sub _torsion_mpz_ui_sub
#define mpz_sub _torsion_mpz_sub
#define mpz_mul_si _torsion_mpz_mul_si
#define mpz_mul_ui _torsion_mpz_mul_ui
#define mpz_mul _torsion_mpz_mul
#define mpz_mul_2exp _torsion_mpz_mul_2exp
#define mpz_addmul_ui _torsion_mpz_addmul_ui
#define mpz_addmul _torsion_mpz_addmul
#define mpz_submul_ui _torsion_mpz_submul_ui
#define mpz_submul _torsion_mpz_submul
#define mpz_cdiv_qr _torsion_mpz_cdiv_qr
#define mpz_fdiv_qr _torsion_mpz_fdiv_qr
#define mpz_tdiv_qr _torsion_mpz_tdiv_qr
#define mpz_cdiv_q _torsion_mpz_cdiv_q
#define mpz_fdiv_q _torsion_mpz_fdiv_q
#define mpz_tdiv_q _torsion_mpz_tdiv_q
#define mpz_cdiv_r _torsion_mpz_cdiv_r
#define mpz_fdiv_r _torsion_mpz_fdiv_r
#define mpz_tdiv_r _torsion_mpz_tdiv_r
#define mpz_cdiv_q_2exp _torsion_mpz_cdiv_q_2exp
#define mpz_fdiv_q_2exp _torsion_mpz_fdiv_q_2exp
#define mpz_tdiv_q_2exp _torsion_mpz_tdiv_q_2exp
#define mpz_cdiv_r_2exp _torsion_mpz_cdiv_r_2exp
#define mpz_fdiv_r_2exp _torsion_mpz_fdiv_r_2exp
#define mpz_tdiv_r_2exp _torsion_mpz_tdiv_r_2exp
#define mpz_mod _torsion_mpz_mod
#define mpz_divexact _torsion_mpz_divexact
#define mpz_divisible_p _torsion_mpz_divisible_p
#define mpz_congruent_p _torsion_mpz_congruent_p
#define mpz_cdiv_qr_ui _torsion_mpz_cdiv_qr_ui
#define mpz_fdiv_qr_ui _torsion_mpz_fdiv_qr_ui
#define mpz_tdiv_qr_ui _torsion_mpz_tdiv_qr_ui
#define mpz_cdiv_q_ui _torsion_mpz_cdiv_q_ui
#define mpz_fdiv_q_ui _torsion_mpz_fdiv_q_ui
#define mpz_tdiv_q_ui _torsion_mpz_tdiv_q_ui
#define mpz_cdiv_r_ui _torsion_mpz_cdiv_r_ui
#define mpz_fdiv_r_ui _torsion_mpz_fdiv_r_ui
#define mpz_tdiv_r_ui _torsion_mpz_tdiv_r_ui
#define mpz_cdiv_ui _torsion_mpz_cdiv_ui
#define mpz_fdiv_ui _torsion_mpz_fdiv_ui
#define mpz_tdiv_ui _torsion_mpz_tdiv_ui
#define mpz_mod_ui _torsion_mpz_mod_ui
#define mpz_divexact_ui _torsion_mpz_divexact_ui
#define mpz_divisible_ui_p _torsion_mpz_divisible_ui_p
#define mpz_gcd_ui _torsion_mpz_gcd_ui
#define mpz_gcd _torsion_mpz_gcd
#define mpz_gcdext _torsion_mpz_gcdext
#define mpn_gcdext _torsion_mpn_gcdext
#define mpz_lcm_ui _torsion_mpz_lcm_ui
#define mpz_lcm _torsion_mpz_lcm
#define mpz_invert _torsion_mpz_invert
#define mpz_jacobi _torsion_mpz_jacobi
#define mpz_sqrtrem _torsion_mpz_sqrtrem
#define mpz_sqrt _torsion_mpz_sqrt
#define mpz_perfect_square_p _torsion_mpz_perfect_square_p
#define mpz_pow_ui _torsion_mpz_pow_ui
#define mpz_ui_pow_ui _torsion_mpz_ui_pow_ui
#define mpz_powm _torsion_mpz_powm
#define mpz_powm_ui _torsion_mpz_powm_ui
#define mpz_powm_sec _torsion_mpz_powm_sec
#define mpz_rootrem _torsion_mpz_rootrem
#define mpz_root _torsion_mpz_root
#define mpz_fac_ui _torsion_mpz_fac_ui
#define mpz_2fac_ui _torsion_mpz_2fac_ui
#define mpz_mfac_uiui _torsion_mpz_mfac_uiui
#define mpz_bin_uiui _torsion_mpz_bin_uiui
#define mpz_probab_prime_p _torsion_mpz_probab_prime_p
#define mpz_tstbit _torsion_mpz_tstbit
#define mpz_setbit _torsion_mpz_setbit
#define mpz_clrbit _torsion_mpz_clrbit
#define mpz_combit _torsion_mpz_combit
#define mpz_com _torsion_mpz_com
#define mpz_and _torsion_mpz_and
#define mpz_ior _torsion_mpz_ior
#define mpz_xor _torsion_mpz_xor
#define mpz_popcount _torsion_mpz_popcount
#define mpz_hamdist _torsion_mpz_hamdist
#define mpz_scan0 _torsion_mpz_scan0
#define mpz_scan1 _torsion_mpz_scan1
#define mpz_fits_slong_p _torsion_mpz_fits_slong_p
#define mpz_fits_ulong_p _torsion_mpz_fits_ulong_p
#define mpz_get_si _torsion_mpz_get_si
#define mpz_get_ui _torsion_mpz_get_ui
#define mpz_get_d _torsion_mpz_get_d
#define mpz_size _torsion_mpz_size
#define mpz_getlimbn _torsion_mpz_getlimbn
#define mpz_realloc2 _torsion_mpz_realloc2
#define mpz_limbs_read _torsion_mpz_limbs_read
#define mpz_limbs_modify _torsion_mpz_limbs_modify
#define mpz_limbs_write _torsion_mpz_limbs_write
#define mpz_limbs_finish _torsion_mpz_limbs_finish
#define mpz_roinit_n _torsion_mpz_roinit_n
#define mpz_set_si _torsion_mpz_set_si
#define mpz_set_ui _torsion_mpz_set_ui
#define mpz_set _torsion_mpz_set
#define mpz_set_d _torsion_mpz_set_d
#define mpz_init_set_si _torsion_mpz_init_set_si
#define mpz_init_set_ui _torsion_mpz_init_set_ui
#define mpz_init_set _torsion_mpz_init_set
#define mpz_init_set_d _torsion_mpz_init_set_d
#define mpz_sizeinbase _torsion_mpz_sizeinbase
#define mpz_get_str _torsion_mpz_get_str
#define mpz_set_str _torsion_mpz_set_str
#define mpz_init_set_str _torsion_mpz_init_set_str
#define mpz_out_str _torsion_mpz_out_str
#define mpz_import _torsion_mpz_import
#define mpz_export _torsion_mpz_export

void mp_set_memory_functions(void *(*)(size_t),
                             void *(*)(void *, size_t, size_t),
                             void (*)(void *, size_t));

void mp_get_memory_functions(void *(**)(size_t),
                             void *(**)(void *, size_t, size_t),
                             void (**)(void *, size_t));

#if defined(MINI_GMP_FIXED_LIMBS) && defined(TORSION_USE_64BIT)
typedef uint64_t mp_limb_t;
MINI_GMP_EXTENSION typedef unsigned __int128 mp_wide_t;
#define GMP_LIMB_BITS 64
#define GMP_NUMB_MASK UINT64_C(0xffffffffffffffff)
#elif defined(MINI_GMP_FIXED_LIMBS)
typedef uint32_t mp_limb_t;
typedef uint64_t mp_wide_t;
#define GMP_LIMB_BITS 32
#define GMP_NUMB_MASK UINT32_C(0xffffffff)
#else
#ifndef MINI_GMP_LIMB_TYPE
#define MINI_GMP_LIMB_TYPE long
#endif
typedef unsigned MINI_GMP_LIMB_TYPE mp_limb_t;
#define GMP_LIMB_BITS ((int)(sizeof(mp_limb_t) * CHAR_BIT))
#define GMP_NUMB_MASK (~((mp_limb_t)0))
#endif

#define GMP_NUMB_BITS GMP_LIMB_BITS
#define GMP_NUMB_MAX GMP_NUMB_MASK
#define GMP_NAIL_BITS 0
#define GMP_NAIL_MASK 0

typedef long mp_size_t;
typedef unsigned long mp_bitcnt_t;

typedef mp_limb_t *mp_ptr;
typedef const mp_limb_t *mp_srcptr;

typedef struct {
  int _mp_alloc;    /* Number of *limbs* allocated and pointed
                       to by the _mp_d field.  */
  int _mp_size;     /* abs(_mp_size) is the number of limbs the
                       last field points to.  If _mp_size is
                       negative this is a negative number.  */
  mp_limb_t *_mp_d; /* Pointer to the limbs.  */
} __mpz_struct;

typedef __mpz_struct mpz_t[1];

typedef __mpz_struct *mpz_ptr;
typedef const __mpz_struct *mpz_srcptr;

extern const int mp_bits_per_limb;

void mpn_copyi(mp_ptr, mp_srcptr, mp_size_t);
void mpn_copyd(mp_ptr, mp_srcptr, mp_size_t);
void mpn_zero(mp_ptr, mp_size_t);

int mpn_cmp(mp_srcptr, mp_srcptr, mp_size_t);
int mpn_zero_p(mp_srcptr, mp_size_t);

mp_limb_t mpn_add_1(mp_ptr, mp_srcptr, mp_size_t, mp_limb_t);
mp_limb_t mpn_add_n(mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);
mp_limb_t mpn_add(mp_ptr, mp_srcptr, mp_size_t, mp_srcptr, mp_size_t);

mp_limb_t mpn_sub_1(mp_ptr, mp_srcptr, mp_size_t, mp_limb_t);
mp_limb_t mpn_sub_n(mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);
mp_limb_t mpn_sub(mp_ptr, mp_srcptr, mp_size_t, mp_srcptr, mp_size_t);

mp_limb_t mpn_mul_1(mp_ptr, mp_srcptr, mp_size_t, mp_limb_t);
mp_limb_t mpn_addmul_1(mp_ptr, mp_srcptr, mp_size_t, mp_limb_t);
mp_limb_t mpn_submul_1(mp_ptr, mp_srcptr, mp_size_t, mp_limb_t);

mp_limb_t mpn_mul(mp_ptr, mp_srcptr, mp_size_t, mp_srcptr, mp_size_t);
void mpn_mul_n(mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);
void mpn_sqr(mp_ptr, mp_srcptr, mp_size_t);
int mpn_perfect_square_p(mp_srcptr, mp_size_t);
mp_size_t mpn_sqrtrem(mp_ptr, mp_ptr, mp_srcptr, mp_size_t);

mp_limb_t mpn_lshift(mp_ptr, mp_srcptr, mp_size_t, unsigned int);
mp_limb_t mpn_rshift(mp_ptr, mp_srcptr, mp_size_t, unsigned int);

mp_bitcnt_t mpn_scan0(mp_srcptr, mp_bitcnt_t);
mp_bitcnt_t mpn_scan1(mp_srcptr, mp_bitcnt_t);

void mpn_com(mp_ptr, mp_srcptr, mp_size_t);
mp_limb_t mpn_neg(mp_ptr, mp_srcptr, mp_size_t);

mp_bitcnt_t mpn_popcount(mp_srcptr, mp_size_t);

mp_limb_t mpn_invert_3by2(mp_limb_t, mp_limb_t);
#define mpn_invert_limb(x) mpn_invert_3by2((x), 0)

void mpn_tdiv_qr(mp_ptr, mp_ptr, mp_size_t,
                 mp_srcptr, mp_size_t,
                 mp_srcptr, mp_size_t);

size_t mpn_get_str(unsigned char *, int, mp_ptr, mp_size_t);
mp_size_t mpn_set_str(mp_ptr, const unsigned char *, size_t, int);

void mpz_init(mpz_t);
void mpz_init2(mpz_t, mp_bitcnt_t);
void mpz_clear(mpz_t);

#define mpz_odd_p(z) (((z)->_mp_size != 0) & (int)(z)->_mp_d[0])
#define mpz_even_p(z) (!mpz_odd_p(z))

int mpz_sgn(const mpz_t);
int mpz_cmp_si(const mpz_t, long);
int mpz_cmp_ui(const mpz_t, unsigned long);
int mpz_cmp(const mpz_t, const mpz_t);
int mpz_cmpabs_ui(const mpz_t, unsigned long);
int mpz_cmpabs(const mpz_t, const mpz_t);
int mpz_cmp_d(const mpz_t, double);
int mpz_cmpabs_d(const mpz_t, double);

void mpz_abs(mpz_t, const mpz_t);
void mpz_neg(mpz_t, const mpz_t);
void mpz_swap(mpz_t, mpz_t);

void mpz_add_ui(mpz_t, const mpz_t, unsigned long);
void mpz_add(mpz_t, const mpz_t, const mpz_t);
void mpz_sub_ui(mpz_t, const mpz_t, unsigned long);
void mpz_ui_sub(mpz_t, unsigned long, const mpz_t);
void mpz_sub(mpz_t, const mpz_t, const mpz_t);

void mpz_mul_si(mpz_t, const mpz_t, long int);
void mpz_mul_ui(mpz_t, const mpz_t, unsigned long int);
void mpz_mul(mpz_t, const mpz_t, const mpz_t);
void mpz_mul_2exp(mpz_t, const mpz_t, mp_bitcnt_t);
void mpz_addmul_ui(mpz_t, const mpz_t, unsigned long int);
void mpz_addmul(mpz_t, const mpz_t, const mpz_t);
void mpz_submul_ui(mpz_t, const mpz_t, unsigned long int);
void mpz_submul(mpz_t, const mpz_t, const mpz_t);

void mpz_cdiv_qr(mpz_t, mpz_t, const mpz_t, const mpz_t);
void mpz_fdiv_qr(mpz_t, mpz_t, const mpz_t, const mpz_t);
void mpz_tdiv_qr(mpz_t, mpz_t, const mpz_t, const mpz_t);
void mpz_cdiv_q(mpz_t, const mpz_t, const mpz_t);
void mpz_fdiv_q(mpz_t, const mpz_t, const mpz_t);
void mpz_tdiv_q(mpz_t, const mpz_t, const mpz_t);
void mpz_cdiv_r(mpz_t, const mpz_t, const mpz_t);
void mpz_fdiv_r(mpz_t, const mpz_t, const mpz_t);
void mpz_tdiv_r(mpz_t, const mpz_t, const mpz_t);

void mpz_cdiv_q_2exp(mpz_t, const mpz_t, mp_bitcnt_t);
void mpz_fdiv_q_2exp(mpz_t, const mpz_t, mp_bitcnt_t);
void mpz_tdiv_q_2exp(mpz_t, const mpz_t, mp_bitcnt_t);
void mpz_cdiv_r_2exp(mpz_t, const mpz_t, mp_bitcnt_t);
void mpz_fdiv_r_2exp(mpz_t, const mpz_t, mp_bitcnt_t);
void mpz_tdiv_r_2exp(mpz_t, const mpz_t, mp_bitcnt_t);

void mpz_mod(mpz_t, const mpz_t, const mpz_t);

void mpz_divexact(mpz_t, const mpz_t, const mpz_t);

int mpz_divisible_p(const mpz_t, const mpz_t);
int mpz_congruent_p(const mpz_t, const mpz_t, const mpz_t);

unsigned long mpz_cdiv_qr_ui(mpz_t, mpz_t, const mpz_t, unsigned long);
unsigned long mpz_fdiv_qr_ui(mpz_t, mpz_t, const mpz_t, unsigned long);
unsigned long mpz_tdiv_qr_ui(mpz_t, mpz_t, const mpz_t, unsigned long);
unsigned long mpz_cdiv_q_ui(mpz_t, const mpz_t, unsigned long);
unsigned long mpz_fdiv_q_ui(mpz_t, const mpz_t, unsigned long);
unsigned long mpz_tdiv_q_ui(mpz_t, const mpz_t, unsigned long);
unsigned long mpz_cdiv_r_ui(mpz_t, const mpz_t, unsigned long);
unsigned long mpz_fdiv_r_ui(mpz_t, const mpz_t, unsigned long);
unsigned long mpz_tdiv_r_ui(mpz_t, const mpz_t, unsigned long);
unsigned long mpz_cdiv_ui(const mpz_t, unsigned long);
unsigned long mpz_fdiv_ui(const mpz_t, unsigned long);
unsigned long mpz_tdiv_ui(const mpz_t, unsigned long);

unsigned long mpz_mod_ui(mpz_t, const mpz_t, unsigned long);

void mpz_divexact_ui(mpz_t, const mpz_t, unsigned long);

int mpz_divisible_ui_p(const mpz_t, unsigned long);

unsigned long mpz_gcd_ui(mpz_t, const mpz_t, unsigned long);
void mpz_gcd(mpz_t, const mpz_t, const mpz_t);
void mpz_gcdext(mpz_t, mpz_t, mpz_t, const mpz_t, const mpz_t);
mp_size_t mpn_gcdext(mp_ptr, mp_ptr, mp_size_t *,
                     mp_ptr, mp_size_t, mp_ptr, mp_size_t);

void mpz_lcm_ui(mpz_t, const mpz_t, unsigned long);
void mpz_lcm(mpz_t, const mpz_t, const mpz_t);
int mpz_invert(mpz_t, const mpz_t, const mpz_t);
int mpz_jacobi(const mpz_t, const mpz_t);

void mpz_sqrtrem(mpz_t, mpz_t, const mpz_t);
void mpz_sqrt(mpz_t, const mpz_t);
int mpz_perfect_square_p(const mpz_t);

void mpz_pow_ui(mpz_t, const mpz_t, unsigned long);
void mpz_ui_pow_ui(mpz_t, unsigned long, unsigned long);
void mpz_powm(mpz_t, const mpz_t, const mpz_t, const mpz_t);
void mpz_powm_ui(mpz_t, const mpz_t, unsigned long, const mpz_t);
void mpz_powm_sec(mpz_t, const mpz_t, const mpz_t, const mpz_t);

void mpz_rootrem(mpz_t, mpz_t, const mpz_t, unsigned long);
int mpz_root(mpz_t, const mpz_t, unsigned long);

void mpz_fac_ui(mpz_t, unsigned long);
void mpz_2fac_ui(mpz_t, unsigned long);
void mpz_mfac_uiui(mpz_t, unsigned long, unsigned long);
void mpz_bin_uiui(mpz_t, unsigned long, unsigned long);

int mpz_probab_prime_p(const mpz_t, int);

int mpz_tstbit(const mpz_t, mp_bitcnt_t);
void mpz_setbit(mpz_t, mp_bitcnt_t);
void mpz_clrbit(mpz_t, mp_bitcnt_t);
void mpz_combit(mpz_t, mp_bitcnt_t);

void mpz_com(mpz_t, const mpz_t);
void mpz_and(mpz_t, const mpz_t, const mpz_t);
void mpz_ior(mpz_t, const mpz_t, const mpz_t);
void mpz_xor(mpz_t, const mpz_t, const mpz_t);

mp_bitcnt_t mpz_popcount(const mpz_t);
mp_bitcnt_t mpz_hamdist(const mpz_t, const mpz_t);
mp_bitcnt_t mpz_scan0(const mpz_t, mp_bitcnt_t);
mp_bitcnt_t mpz_scan1(const mpz_t, mp_bitcnt_t);

int mpz_fits_slong_p(const mpz_t);
int mpz_fits_ulong_p(const mpz_t);
long int mpz_get_si(const mpz_t);
unsigned long int mpz_get_ui(const mpz_t);
double mpz_get_d(const mpz_t);
size_t mpz_size(const mpz_t);
mp_limb_t mpz_getlimbn(const mpz_t, mp_size_t);

void mpz_realloc2(mpz_t, mp_bitcnt_t);
mp_srcptr mpz_limbs_read(mpz_srcptr);
mp_ptr mpz_limbs_modify(mpz_t, mp_size_t);
mp_ptr mpz_limbs_write(mpz_t, mp_size_t);
void mpz_limbs_finish(mpz_t, mp_size_t);
mpz_srcptr mpz_roinit_n(mpz_t, mp_srcptr, mp_size_t);

#define MPZ_ROINIT_N(xp, xs) {{0, (xs), (xp)}}

void mpz_set_si(mpz_t, signed long int);
void mpz_set_ui(mpz_t, unsigned long int);
void mpz_set(mpz_t, const mpz_t);
void mpz_set_d(mpz_t, double);

void mpz_init_set_si(mpz_t, signed long int);
void mpz_init_set_ui(mpz_t, unsigned long int);
void mpz_init_set(mpz_t, const mpz_t);
void mpz_init_set_d(mpz_t, double);

size_t mpz_sizeinbase(const mpz_t, int);
char *mpz_get_str(char *, int, const mpz_t);
int mpz_set_str(mpz_t, const char *, int);
int mpz_init_set_str(mpz_t, const char *, int);

/* This long list taken from gmp.h. */
/* For reference, "defined(EOF)" cannot be used here.  In g++ 2.95.4,
   <iostream> defines EOF but not FILE.  */
#if defined(FILE)                                          \
  || defined(H_STDIO)                                      \
  || defined(_H_STDIO)               /* AIX */             \
  || defined(_STDIO_H)               /* glibc, Sun, SCO */ \
  || defined(_STDIO_H_)              /* BSD, OSF */        \
  || defined(__STDIO_H)              /* Borland */         \
  || defined(__STDIO_H__)            /* IRIX */            \
  || defined(_STDIO_INCLUDED)        /* HPUX */            \
  || defined(__dj_include_stdio_h_)  /* DJGPP */           \
  || defined(_FILE_DEFINED)          /* Microsoft */       \
  || defined(__STDIO__)              /* Apple MPW MrC */   \
  || defined(_MSL_STDIO_H)           /* Metrowerks */      \
  || defined(_STDIO_H_INCLUDED)      /* QNX4 */            \
  || defined(_ISO_STDIO_ISO_H)       /* Sun C++ */         \
  || defined(__STDIO_LOADED)         /* VMS */
size_t mpz_out_str(FILE *, int, const mpz_t);
#endif

void mpz_import(mpz_t, size_t, int, size_t, int, size_t, const void *);
void *mpz_export(void *, size_t *, int, size_t, int, size_t, const mpz_t);

#if defined(__cplusplus)
}
#endif
#endif /* __MINI_GMP_H__ */
