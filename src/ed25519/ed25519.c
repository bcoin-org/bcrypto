/*
  Public domain by Andrew M. <liquidsun@gmail.com>

  Ed25519 reference implementation using Ed25519-donna
*/

#include "ed25519-donna.h"
#include "ed25519.h"
#include "ed25519-randombytes.h"
#include "ed25519-hash.h"

/*
  Generates a (extsk[0..31]) and aExt (extsk[32..63])
*/

DONNA_INLINE static void
bcrypto_ed25519_extsk(hash_512bits extsk, const bcrypto_ed25519_secret_key sk) {
  bcrypto_ed25519_hash(extsk, sk, 32);
  extsk[0] &= 248;
  extsk[31] &= 127;
  extsk[31] |= 64;
}

static void
bcrypto_ed25519_hram(
  hash_512bits hram,
  const bcrypto_ed25519_signature RS,
  const bcrypto_ed25519_public_key pk,
  const unsigned char *m,
  size_t mlen
) {
  bcrypto_ed25519_hash_context ctx;
  bcrypto_ed25519_hash_init(&ctx);
  bcrypto_ed25519_hash_update(&ctx, RS, 32);
  bcrypto_ed25519_hash_update(&ctx, pk, 32);
  bcrypto_ed25519_hash_update(&ctx, m, mlen);
  bcrypto_ed25519_hash_final(&ctx, hram);
}

void
bcrypto_ed25519_publickey(
  const bcrypto_ed25519_secret_key sk,
  bcrypto_ed25519_public_key pk
) {
  bignum256modm a;
  ge25519 ALIGN(16) A;
  hash_512bits extsk;

  /* A = aB */
  bcrypto_ed25519_extsk(extsk, sk);
  expand256_modm(a, extsk, 32);
  ge25519_scalarmult_base_niels(&A, ge25519_niels_base_multiples, a);
  ge25519_pack(pk, &A);
}

void
bcrypto_ed25519_sign(
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_secret_key sk,
  const bcrypto_ed25519_public_key pk,
  bcrypto_ed25519_signature RS
) {
  bcrypto_ed25519_hash_context ctx;
  bignum256modm r, S, a;
  ge25519 ALIGN(16) R;
  hash_512bits extsk, hashr, hram;

  bcrypto_ed25519_extsk(extsk, sk);

  /* r = H(aExt[32..64], m) */
  bcrypto_ed25519_hash_init(&ctx);
  bcrypto_ed25519_hash_update(&ctx, extsk + 32, 32);
  bcrypto_ed25519_hash_update(&ctx, m, mlen);
  bcrypto_ed25519_hash_final(&ctx, hashr);
  expand256_modm(r, hashr, 64);

  /* R = rB */
  ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, r);
  ge25519_pack(RS, &R);

  /* S = H(R,A,m).. */
  bcrypto_ed25519_hram(hram, RS, pk, m, mlen);
  expand256_modm(S, hram, 64);

  /* S = H(R,A,m)a */
  expand256_modm(a, extsk, 32);
  mul256_modm(S, S, a);

  /* S = (r + H(R,A,m)a) */
  add256_modm(S, S, r);

  /* S = (r + H(R,A,m)a) mod L */
  contract256_modm(RS + 32, S);
}

int
bcrypto_ed25519_sign_open(
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_public_key pk,
  const bcrypto_ed25519_signature RS
) {
  ge25519 ALIGN(16) R, A;
  hash_512bits hash;
  bignum256modm hram, S;
  unsigned char checkR[32];

  if ((RS[63] & 224) || !ge25519_unpack_negative_vartime(&A, pk))
    return -1;

  /* hram = H(R,A,m) */
  bcrypto_ed25519_hram(hash, RS, pk, m, mlen);
  expand256_modm(hram, hash, 64);

  /* S */
  expand256_modm(S, RS + 32, 32);

  /* SB - H(R,A,m)A */
  ge25519_double_scalarmult_vartime(&R, &A, hram, S);
  ge25519_pack(checkR, &R);

  /* check that R = SB - H(R,A,m)A */
  return bcrypto_ed25519_verify(RS, checkR, 32) ? 0 : -1;
}

int
bcrypto_ed25519_verify_key(const bcrypto_ed25519_public_key pk) {
  ge25519 ALIGN(16) A;

  if (!ge25519_unpack_negative_vartime(&A, pk))
    return -1;

  return 0;
}

#include "ed25519-donna-batchverify.h"

/*
  Fast Curve25519 basepoint scalar multiplication
*/

void
bcrypto_curved25519_scalarmult_basepoint(
  bcrypto_curved25519_key pk,
  const bcrypto_curved25519_key e
) {
  bcrypto_curved25519_key ec;
  bignum256modm s;
  bignum25519 ALIGN(16) yplusz, zminusy;
  ge25519 ALIGN(16) p;
  size_t i;

  /* clamp */
  for (i = 0; i < 32; i++) ec[i] = e[i];
  ec[0] &= 248;
  ec[31] &= 127;
  ec[31] |= 64;

  expand_raw256_modm(s, ec);

  /* scalar * basepoint */
  ge25519_scalarmult_base_niels(&p, ge25519_niels_base_multiples, s);

  /* u = (y + z) / (z - y) */
  curve25519_add(yplusz, p.y, p.z);
  curve25519_sub(zminusy, p.z, p.y);
  curve25519_recip(zminusy, zminusy);
  curve25519_mul(yplusz, yplusz, zminusy);
  curve25519_contract(pk, yplusz);
}

int
bcrypto_ed25519_pubkey_convert(
  bcrypto_curved25519_key out,
  const bcrypto_ed25519_public_key pk
) {
  bignum25519 ALIGN(16) yplusz, zminusy;
  ge25519 ALIGN(16) p;

  /* ed25519 pubkey -> ed25519 point */
  if (!ge25519_unpack_negative_vartime(&p, pk))
    return -1;

  /* ed25519 point -> x25519 point */
  curve25519_add(yplusz, p.y, p.z);
  curve25519_sub(zminusy, p.z, p.y);
  curve25519_recip(zminusy, zminusy);
  curve25519_mul(yplusz, yplusz, zminusy);

  /* output secret (little-endian x coord) */
  curve25519_contract(out, yplusz);

  return 0;
}
