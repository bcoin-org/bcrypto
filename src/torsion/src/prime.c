#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <torsion/drbg.h>

#include "mpi.h"
#include "prime.h"

void
mpz_random_bits(mpz_t ret, size_t bits, drbg_t *rng) {
  /* Assumes nails are not enabled. */
  size_t size = (bits + GMP_LIMB_BITS - 1) / GMP_LIMB_BITS;
  size_t low = bits % GMP_LIMB_BITS;
  mp_limb_t *limbs = mpz_limbs_write(ret, size);

  drbg_generate(rng, limbs, size * sizeof(mp_limb_t));

  if (low != 0)
    limbs[size - 1] &= ((mp_limb_t)1 << low) - 1;

  mpz_limbs_finish(ret, size);

  assert(mpz_bitlen(ret) <= bits);
}

void
mpz_random_int(mpz_t ret, const mpz_t max, drbg_t *rng) {
  size_t bits = mpz_bitlen(max);

  mpz_set(ret, max);

  if (bits > 0) {
    while (mpz_cmpabs(ret, max) >= 0)
      mpz_random_bits(ret, bits, rng);

    if (mpz_sgn(max) < 0)
      mpz_neg(ret, ret);
  }
}

static int
mpz_is_prime_mr(const mpz_t n, unsigned long reps, int force2, drbg_t *rng) {
  mpz_t nm1, nm3, q, x, y;
  unsigned long k, i, j;
  int ret = 0;

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
  k = mpz_scan1(nm1, 0);

  /* q = nm1 >> k */
  mpz_tdiv_q_2exp(q, nm1, k);

  for (i = 0; i < reps; i++) {
    if (i == reps - 1 && force2) {
      /* x = 2 */
      mpz_set_ui(x, 2);
    } else {
      /* x = random integer in [2,n-1] */
      mpz_random_int(x, nm3, rng);
      mpz_add_ui(x, x, 2);
    }

    /* y = x^q mod n */
    mpz_powm(y, x, q, n);

    /* if y == 1 or y == -1 mod n */
    if (mpz_cmp_ui(y, 1) == 0 || mpz_cmp(y, nm1) == 0)
      continue;

    for (j = 1; j < k; j++) {
      /* y = y^2 mod n */
      mpz_mul(y, y, y);
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

static int
mpz_is_prime_lucas(const mpz_t n, unsigned long limit) {
  mpz_t d, s, nm2, vk, vk1, t1, t2, t3;
  unsigned long i, p, r, t;
  int ret = 0;
  int j;

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
      if (mpz_perfect_square_p(n))
        goto fail;
    }

    p += 1;
  }

  /* s = n + 1 */
  mpz_add_ui(s, n, 1);

  /* r = s factors of 2 */
  r = mpz_scan1(s, 0);

  /* nm2 = n - 2 */
  mpz_sub_ui(nm2, n, 2);

  /* vk = 2 */
  mpz_set_ui(vk, 2);

  /* vk1 = p */
  mpz_set_ui(vk1, p);

  /* s >>= r */
  mpz_tdiv_q_2exp(s, s, r);

  for (i = mpz_bitlen(s) + 1; i-- > 0;) {
    /* if floor(s / 2^i) mod 2 == 1 */
    if (mpz_tstbit(s, i)) {
      /* vk = (vk * vk1 + n - p) mod n */
      /* vk1 = (vk1^2 + nm2) mod n */
      mpz_mul(t1, vk, vk1);
      mpz_add(t1, t1, n);
      mpz_sub_ui(t1, t1, p);
      mpz_mod(vk, t1, n);
      mpz_mul(t1, vk1, vk1);
      mpz_add(t1, t1, nm2);
      mpz_mod(vk1, t1, n);
    } else {
      /* vk1 = (vk * vk1 + n - p) mod n */
      /* vk = (vk^2 + nm2) mod n */
      mpz_mul(t1, vk, vk1);
      mpz_add(t1, t1, n);
      mpz_sub_ui(t1, t1, p);
      mpz_mod(vk1, t1, n);
      mpz_mul(t1, vk, vk);
      mpz_add(t1, t1, nm2);
      mpz_mod(vk, t1, n);
    }
  }

  /* if vk == 2 or vk == nm2 */
  if (mpz_cmp_ui(vk, 2) == 0 || mpz_cmp(vk, nm2) == 0) {
    /* t3 = abs(vk * p - vk1 * 2) mod n */
    mpz_mul_ui(t1, vk, p);
    mpz_mul_2exp(t2, vk1, 1);

    if (mpz_cmp(t1, t2) < 0)
      mpz_swap(t1, t2);

    mpz_sub(t1, t1, t2);
    mpz_mod(t3, t1, n);

    /* if t3 == 0 */
    if (mpz_sgn(t3) == 0)
      goto succeed;
  }

  for (t = 1; t < r; t++) {
    /* if vk == 0 */
    if (mpz_sgn(vk) == 0)
      goto succeed;

    /* if vk == 2 */
    if (mpz_cmp_ui(vk, 2) == 0)
      goto fail;

    /* vk = (vk^2 - 2) mod n */
    mpz_mul(t1, vk, vk);
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
mpz_is_prime(const mpz_t p, unsigned long rounds, drbg_t *rng) {
  static const mp_limb_t primes_a =
    3ul * 5ul * 7ul * 11ul * 13ul * 17ul * 19ul * 23ul * 37ul;
  static const mp_limb_t primes_b = 29ul * 31ul * 41ul * 43ul * 47ul * 53ul;
  mp_limb_t ra, rb;

  if (mpz_sgn(p) <= 0)
    return 0;

  if (mpz_cmp_ui(p, 64) < 0) {
    static const uint64_t prime_mask = 0ull
      | 1ull <<  2 | 1ull <<  3 | 1ull <<  5 | 1ull << 7
      | 1ull << 11 | 1ull << 13 | 1ull << 17 | 1ull << 19
      | 1ull << 23 | 1ull << 29 | 1ull << 31 | 1ull << 37
      | 1ull << 41 | 1ull << 43 | 1ull << 47 | 1ull << 53
      | 1ull << 59 | 1ull << 61;

    return (prime_mask >> mpz_get_ui(p)) & 1;
  }

  if (mpz_even_p(p))
    return 0;

  ra = mpz_fdiv_ui(p, primes_a);
  rb = mpz_fdiv_ui(p, primes_b);

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

  if (!mpz_is_prime_mr(p, rounds + 1, 1, rng))
    return 0;

  if (!mpz_is_prime_lucas(p, 0))
    return 0;

  return 1;
}

static void
mpz_set_u64(mpz_t r, uint64_t num) {
  mpz_set_ui(r, num >> 32);
  mpz_mul_2exp(r, r, 32);
  mpz_add_ui(r, r, num & 0xfffffffful);
}

static uint64_t
mpz_get_u64(const mpz_t x) {
  if (GMP_LIMB_BITS < 64) {
    size_t LOCAL_GMP_LIMB_BITS = GMP_LIMB_BITS;
    size_t i = 64 / GMP_LIMB_BITS;
    uint64_t w = 0;

    while (i--) {
      w <<= LOCAL_GMP_LIMB_BITS;
      w |= mpz_getlimbn(x, i);
    }

    return w;
  }

  return mpz_getlimbn(x, 0);
}

void
mpz_random_prime(mpz_t ret, size_t bits, drbg_t *rng) {
  static const uint64_t primes[15] =
    { 3,  5,  7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53 };
  static const uint64_t product = 16294579238595022365ull;
  uint64_t mod, delta, m, p;
  mpz_t prod, tmp;
  size_t i;

  assert(bits > 1);

  mpz_init(prod);
  mpz_init(tmp);

  mpz_set_u64(prod, product);

  for (;;) {
    mpz_random_bits(ret, bits, rng);

    mpz_setbit(ret, bits - 1);
    mpz_setbit(ret, bits - 2);
    mpz_setbit(ret, 0);

    mpz_mod(tmp, ret, prod);
    mod = mpz_get_u64(tmp);

    for (delta = 0; delta < (1ull << 20); delta += 2) {
      m = mod + delta;

      for (i = 0; i < sizeof(primes) / sizeof(primes[0]); i++) {
        p = primes[i];

        if ((m % p) == 0 && (bits > 6 || m != p))
          goto next;
      }

      mpz_add_ui(ret, ret, (mp_limb_t)delta);

      break;
next:
      ;
    }

    if (mpz_bitlen(ret) != bits)
      continue;

    if (!mpz_is_prime(ret, 20, rng))
      continue;

    break;
  }

  mpz_cleanse(prod);
  mpz_cleanse(tmp);
}
