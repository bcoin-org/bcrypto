#ifndef _TORSION_PRIME_H
#define _TORSION_PRIME_H

#include <stdlib.h>
#include <torsion/drbg.h>

#include "mpi.h"

#define mpz_random_bits _torsion_mpz_random_bits
#define mpz_random_int _torsion_mpz_random_int
#define mpz_is_prime _torsion_mpz_is_prime
#define mpz_random_prime _torsion_mpz_random_prime

void
mpz_random_bits(mpz_t ret, size_t bits, drbg_t *rng);

void
mpz_random_int(mpz_t ret, const mpz_t max, drbg_t *rng);

int
mpz_is_prime(const mpz_t p, unsigned long rounds, drbg_t *rng);

void
mpz_random_prime(mpz_t ret, size_t bits, drbg_t *rng);

#endif /* _TORSION_PRIME_H */
