/*
  Public domain by Andrew M. <liquidsun@gmail.com>

  Ed25519 reference implementation using Ed25519-donna
*/

#include "ed25519-donna.h"
#include "ed25519.h"
#include "ed25519-randombytes.h"
#include "ed25519-hash.h"

static const unsigned char ED25519_PREFIX[] =
  "SigEd25519 no Ed25519 collisions";

/*
  Generates a (extsk[0..31]) and aExt (extsk[32..63])
*/

DONNA_INLINE static void
bcrypto_ed25519_extsk(hash_512bits extsk, const bcrypto_ed25519_privkey_t sk) {
  bcrypto_ed25519_hash(extsk, sk, 32);
  extsk[0] &= 248;
  extsk[31] &= 127;
  extsk[31] |= 64;
}

static void
bcrypto_ed25519_hprefix(
  bcrypto_ed25519_hash_t *hctx,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len
) {
  if (ph != -1) {
    bcrypto_ed25519_hash_update(hctx, ED25519_PREFIX,
                                sizeof(ED25519_PREFIX) - 1);

    unsigned char slab[2] = {
      (unsigned char)ph,
      (unsigned char)ctx_len
    };

    bcrypto_ed25519_hash_update(hctx, &slab[0], 2);
    bcrypto_ed25519_hash_update(hctx, ctx, ctx_len);
  }
}

static void
bcrypto_ed25519_hram(
  hash_512bits hram,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len,
  const bcrypto_ed25519_sig_t RS,
  const bcrypto_ed25519_pubkey_t pk,
  const unsigned char *m,
  size_t mlen
) {
  bcrypto_ed25519_hash_t hctx;
  bcrypto_ed25519_hash_init(&hctx);
  bcrypto_ed25519_hprefix(&hctx, ph, ctx, ctx_len);
  bcrypto_ed25519_hash_update(&hctx, RS, 32);
  bcrypto_ed25519_hash_update(&hctx, pk, 32);
  bcrypto_ed25519_hash_update(&hctx, m, mlen);
  bcrypto_ed25519_hash_final(&hctx, hram);
}

#include "ed25519-donna-batchverify.h"

int
bcrypto_ed25519_pubkey_from_scalar(
  bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t sk
) {
  bignum256modm a;
  ge25519 ALIGN(16) A;

  /* A = aB */
  expand256_modm(a, sk, 32);
  ge25519_scalarmult_base_niels(&A, ge25519_niels_base_multiples, a);

  ge25519_pack(pk, &A);

  return 1;
}

int
bcrypto_ed25519_pubkey_create(
  bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_privkey_t sk
) {
  hash_512bits extsk;
  bcrypto_ed25519_extsk(extsk, sk);
  return bcrypto_ed25519_pubkey_from_scalar(pk, extsk);
}

int
bcrypto_ed25519_verify(
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_pubkey_t pk,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len,
  const bcrypto_ed25519_sig_t RS
) {
  ge25519 ALIGN(16) R, A;
  hash_512bits hash;
  bignum256modm hram, S;
  unsigned char checkR[32];

  if (!is_canonical256_modm(RS + 32)
      || !ge25519_is_canonical(RS)
      || !ge25519_unpack_vartime(&A, pk)) {
    return 0;
  }

  /* hram = H(R,A,m) */
  bcrypto_ed25519_hram(hash, ph, ctx, ctx_len, RS, pk, m, mlen);
  expand256_modm(hram, hash, 64);

  /* S */
  expand256_modm(S, RS + 32, 32);

  /* SB - H(R,A,m)A */
  ge25519_neg(&A, &A);
  ge25519_double_scalarmult_vartime(&R, &A, hram, S);
  ge25519_pack(checkR, &R);

  /* check that R = SB - H(R,A,m)A */
  return bcrypto_ed25519_equal(RS, checkR, 32);
}

int
bcrypto_ed25519_verify_single(
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_pubkey_t pk,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len,
  const bcrypto_ed25519_sig_t RS
) {
  ge25519 ALIGN(16) R, A;
  hash_512bits hash;
  bignum256modm hram, S;
  unsigned char expectR[32];
  unsigned char checkR[32];

  if (!is_canonical256_modm(RS + 32)
      || !ge25519_unpack_vartime(&R, RS)
      || !ge25519_unpack_vartime(&A, pk)) {
    return 0;
  }

  ge25519_mulh(&R, &R);
  ge25519_pack(expectR, &R);

  /* hram = H(R,A,m) */
  bcrypto_ed25519_hram(hash, ph, ctx, ctx_len, RS, pk, m, mlen);
  expand256_modm(hram, hash, 64);

  /* Sh */
  expand256_modm(S, RS + 32, 32);
  mulh256_modm(S, S);

  /* ShB - H(R,A,m)Ah */
  ge25519_mulh(&A, &A);
  ge25519_neg(&A, &A);
  ge25519_double_scalarmult_vartime(&R, &A, hram, S);
  ge25519_pack(checkR, &R);

  /* check that Rh = ShB - H(R,A,m)Ah */
  return bcrypto_ed25519_equal(expectR, checkR, 32);
}

int
bcrypto_ed25519_pubkey_verify(const bcrypto_ed25519_pubkey_t pk) {
  ge25519 ALIGN(16) A;
  return ge25519_unpack(&A, pk);
}

int
bcrypto_ed25519_pubkey_is_infinity(const bcrypto_ed25519_pubkey_t pk) {
  return ge25519_is_one(pk);
}

int
bcrypto_ed25519_pubkey_is_small(const bcrypto_ed25519_pubkey_t pk) {
  ge25519 ALIGN(16) A;

  if (!ge25519_unpack(&A, pk))
    return 0;

  return ge25519_is_small(&A);
}

int
bcrypto_ed25519_pubkey_has_torsion(const bcrypto_ed25519_pubkey_t pk) {
  ge25519 ALIGN(16) A;

  if (!ge25519_unpack(&A, pk))
    return 0;

  return ge25519_has_torsion(&A);
}

int
bcrypto_x25519_pubkey_verify(const bcrypto_x25519_pubkey_t pk) {
  bignum25519 ALIGN(16) x;
  curve25519_expand(x, pk);
  return curve25519_valid_x(x);
}

int
bcrypto_x25519_pubkey_is_small(const bcrypto_x25519_pubkey_t pk) {
  bignum25519 ALIGN(16) x, z;

  curve25519_expand(x, pk);
  curve25519_set_word(z, 1);

  if (!curve25519_valid_x(x))
    return 0;

  curve25519_double(x, z, x, z);
  curve25519_double(x, z, x, z);
  curve25519_double(x, z, x, z);

  return curve25519_is_zero(z);
}

int
bcrypto_x25519_pubkey_has_torsion(const bcrypto_x25519_pubkey_t pk) {
  static const unsigned char k[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
  };

  bignum25519 ALIGN(16) x, z;
  int zero;

  curve25519_expand(x, pk);

  if (!curve25519_valid_x(x))
    return 0;

  zero = curve25519_is_zero(x);

  curve25519_ladder(x, z, x, k);

  return (curve25519_is_zero(z) ^ 1) | zero;
}

void
bcrypto_ed25519_privkey_expand(
  unsigned char out[64],
  const bcrypto_ed25519_privkey_t sk
) {
  bcrypto_ed25519_extsk(out, sk);
}

void
bcrypto_ed25519_privkey_convert(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_privkey_t sk
) {
  hash_512bits extsk;
  bcrypto_ed25519_extsk(extsk, sk);
  memcpy(out, extsk, 32);
}

int
bcrypto_ed25519_pubkey_convert(
  bcrypto_x25519_pubkey_t out,
  int *sign,
  const bcrypto_ed25519_pubkey_t pk
) {
  bignum25519 ALIGN(16) u, uz, v, vz, z;
  ge25519 ALIGN(16) p;
  int ret = 1;

  /* decode */
  ret &= ge25519_unpack(&p, pk);

  /* u = (1 + y) / (1 - y) */
  curve25519_add(u, p.z, p.y);
  curve25519_sub(uz, p.z, p.y);

  /* v = sqrt(-486664) * u / x */
  curve25519_mul(v, curve25519_sqrt_m486664, u);
  curve25519_mul(vz, p.x, uz);

  curve25519_mul(u, u, vz);
  curve25519_mul(v, v, uz);
  curve25519_mul(z, uz, vz);

  /* exceptional case */
  ret &= curve25519_is_zero(z) ^ 1;

  curve25519_recip(z, z);
  curve25519_mul(u, u, z);
  curve25519_mul(v, v, z);

  if (sign != NULL)
    *sign = curve25519_is_odd(v);

  curve25519_contract(out, u);

  return ret;
}

int
bcrypto_x25519_pubkey_convert(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_x25519_pubkey_t pk,
  int sign
) {
  static const bignum25519 one = {1};
  ge25519 ALIGN(16) p, o;
  bignum25519 ALIGN(16) u, v, xz, yz;
  int ret;

  /* decode */
  curve25519_expand(u, pk);
  ret = curve25519_solve_y(v, u);
  curve25519_neg_conditional(v, v, curve25519_is_odd(v) ^ sign);

  /* x = sqrt(-486664) * u / v */
  curve25519_mul(p.x, curve25519_sqrt_m486664, u);
  curve25519_copy(xz, v);

  /* y = (u - 1) / (u + 1) */
  curve25519_sub(p.y, u, one);
  curve25519_add(yz, u, one);

  curve25519_mul(p.x, p.x, yz);
  curve25519_mul(p.y, p.y, xz);
  curve25519_mul(p.z, xz, yz);

  /* exceptional case */
  ge25519_set_neutral(&o);
  ge25519_swap_conditional(&p, &o, curve25519_is_zero(p.z));

  ge25519_pack(out, &p);

  return ret;
}

int
bcrypto_ed25519_derive_with_scalar(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t sk
) {
  bignum256modm k;
  ge25519 ALIGN(16) r, p;
  bcrypto_ed25519_scalar_t ec;
  size_t i;

  /* clamp */
  for (i = 0; i < 32; i++)
    ec[i] = sk[i];

  ec[0] &= 248;
  ec[31] &= 127;
  ec[31] |= 64;

  expand_raw256_modm(k, ec);

  if (!ge25519_unpack(&p, pk))
    return 0;

  ge25519_scalarmult(&r, &p, k);
  ge25519_pack(out, &r);

  return ge25519_is_one(out) ^ 1;
}

int
bcrypto_ed25519_derive(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_privkey_t sk
) {
  hash_512bits extsk;
  bcrypto_ed25519_extsk(extsk, sk);
  return bcrypto_ed25519_derive_with_scalar(out, pk, extsk);
}

int
bcrypto_x25519_pubkey_create(
  bcrypto_x25519_pubkey_t out,
  const bcrypto_ed25519_scalar_t sk
) {
  bcrypto_ed25519_scalar_t k;
  bignum256modm a;
  ge25519 ALIGN(16) A;
  bignum25519 ALIGN(16) x, z;
  size_t i;

  for (i = 0; i < 32; i++)
    k[i] = sk[i];

  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;

  expand256_modm(a, k, 32);
  ge25519_scalarmult_base_niels(&A, ge25519_niels_base_multiples, a);

  curve25519_add(x, A.z, A.y);
  curve25519_sub(z, A.z, A.y);

  if (curve25519_is_zero(z))
    return 0;

  curve25519_recip(z, z);
  curve25519_mul(x, x, z);
  curve25519_contract(out, x);

  return 1;
}

int
bcrypto_x25519_derive(
  bcrypto_x25519_pubkey_t out,
  const bcrypto_x25519_pubkey_t xpk,
  const bcrypto_ed25519_scalar_t sk
) {
  bcrypto_ed25519_scalar_t k;
  bignum25519 ALIGN(16) x, z;
  static const unsigned char zero[32] = {0};
  size_t i;

  for (i = 0; i < 32; i++)
    k[i] = sk[i];

  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;

  curve25519_expand(x, xpk);
  curve25519_ladder(x, z, x, k);
  curve25519_recip(z, z);
  curve25519_mul(x, x, z);
  curve25519_contract(out, x);

  return bcrypto_ed25519_equal(out, zero, 32) ^ 1;
}

int
bcrypto_ed25519_scalar_is_zero(const bcrypto_ed25519_scalar_t sk) {
  bignum256modm k;
  expand256_modm(k, sk, 32);
  return iszero256_modm_batch(k);
}

int
bcrypto_ed25519_scalar_tweak_add(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_scalar_t sk,
  const bcrypto_ed25519_scalar_t tweak
) {
  bignum256modm k, t;

  expand256_modm(k, sk, 32);
  expand256_modm(t, tweak, 32);

  add256_modm(k, k, t);

  contract256_modm(out, k);

  return 1;
}

int
bcrypto_ed25519_scalar_tweak_mul(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_scalar_t sk,
  const bcrypto_ed25519_scalar_t tweak
) {
  bignum256modm k, t;

  expand256_modm(k, sk, 32);
  expand256_modm(t, tweak, 32);

  mul256_modm(k, k, t);

  contract256_modm(out, k);

  return 1;
}

void
bcrypto_ed25519_scalar_reduce(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_scalar_t sk
) {
  bignum256modm k;
  expand256_modm(k, sk, 32);
  contract256_modm(out, k);
}

int
bcrypto_ed25519_scalar_negate(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_scalar_t sk
) {
  bignum256modm k;

  expand256_modm(k, sk, 32);
  negate256_modm(k, k);

  contract256_modm(out, k);

  return 1;
}

int
bcrypto_ed25519_scalar_invert(
  bcrypto_ed25519_scalar_t out,
  const bcrypto_ed25519_scalar_t sk
) {
  bignum256modm k;

  expand256_modm(k, sk, 32);
  recip256_modm(k, k);

  if (iszero256_modm_batch(k))
    return 0;

  contract256_modm(out, k);

  return 1;
}

int
bcrypto_ed25519_pubkey_tweak_add(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t tweak
) {
  ge25519 ALIGN(16) T, k;
  bignum256modm t;

  if (!ge25519_unpack(&k, pk))
    return 0;

  expand256_modm(t, tweak, 32);

  ge25519_scalarmult_base_niels(&T, ge25519_niels_base_multiples, t);

  ge25519_add(&k, &k, &T);
  ge25519_pack(out, &k);

  return 1;
}

int
bcrypto_ed25519_pubkey_tweak_mul(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t tweak
) {
  ge25519 ALIGN(16) T, k;
  bignum256modm t;

  if (!ge25519_unpack(&k, pk))
    return 0;

  expand_raw256_modm(t, tweak);

  ge25519_scalarmult(&T, &k, t);
  ge25519_pack(out, &T);

  return 1;
}

int
bcrypto_ed25519_pubkey_add(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk1,
  const bcrypto_ed25519_pubkey_t pk2
) {
  ge25519 ALIGN(16) k1, k2;

  if (!ge25519_unpack(&k1, pk1))
    return 0;

  if (!ge25519_unpack(&k2, pk2))
    return 0;

  ge25519_add(&k1, &k1, &k2);
  ge25519_pack(out, &k1);

  return 1;
}

int
bcrypto_ed25519_pubkey_combine(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t *pks,
  size_t length
) {
  ge25519 ALIGN(16) k1, k2;
  size_t i;

  ge25519_set_neutral(&k1);

  for (i = 0; i < length; i++) {
    if (!ge25519_unpack(&k2, pks[i]))
      return 0;

    ge25519_add(&k1, &k1, &k2);
  }

  ge25519_pack(out, &k1);

  return 1;
}

int
bcrypto_ed25519_pubkey_negate(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk
) {
  ge25519 ALIGN(16) k;

  if (!ge25519_unpack(&k, pk))
    return 0;

  ge25519_neg(&k, &k);
  ge25519_pack(out, &k);

  return 1;
}

int
bcrypto_ed25519_sign_with_scalar(
  bcrypto_ed25519_sig_t RS,
  const unsigned char *m,
  size_t mlen,
  const unsigned char extsk[64],
  const bcrypto_ed25519_pubkey_t pk,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len
) {
  bcrypto_ed25519_hash_t hctx;
  bignum256modm r, S, a;
  ge25519 ALIGN(16) R;
  hash_512bits hashr, hram;

  /* r = H(aExt[32..64], m) */
  bcrypto_ed25519_hash_init(&hctx);
  bcrypto_ed25519_hprefix(&hctx, ph, ctx, ctx_len);
  bcrypto_ed25519_hash_update(&hctx, extsk + 32, 32);
  bcrypto_ed25519_hash_update(&hctx, m, mlen);
  bcrypto_ed25519_hash_final(&hctx, hashr);
  expand256_modm(r, hashr, 64);

  /* R = rB */
  ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, r);
  ge25519_pack(RS, &R);

  /* S = H(R,A,m).. */
  bcrypto_ed25519_hram(hram, ph, ctx, ctx_len, RS, pk, m, mlen);
  expand256_modm(S, hram, 64);

  /* S = H(R,A,m)a */
  expand256_modm(a, extsk, 32);
  mul256_modm(S, S, a);

  /* S = (r + H(R,A,m)a) */
  add256_modm(S, S, r);

  /* S = (r + H(R,A,m)a) mod L */
  contract256_modm(RS + 32, S);

  return 1;
}

int
bcrypto_ed25519_sign(
  bcrypto_ed25519_sig_t RS,
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_privkey_t sk,
  const bcrypto_ed25519_pubkey_t pk,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len
) {
  hash_512bits extsk;
  bcrypto_ed25519_extsk(extsk, sk);
  return bcrypto_ed25519_sign_with_scalar(RS, m, mlen, extsk, pk, ph, ctx, ctx_len);
}

int
bcrypto_ed25519_sign_tweak_add(
  bcrypto_ed25519_sig_t RS,
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_privkey_t sk,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t tweak,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len
) {
  hash_512bits extsk, prefix;
  bcrypto_ed25519_pubkey_t tk;
  bcrypto_ed25519_hash_t hctx;

  bcrypto_ed25519_extsk(extsk, sk);

  if (!bcrypto_ed25519_scalar_tweak_add(extsk, extsk, tweak))
    return 0;

  bcrypto_ed25519_hash_init(&hctx);
  bcrypto_ed25519_hash_update(&hctx, extsk + 32, 32);
  bcrypto_ed25519_hash_update(&hctx, tweak, 32);
  bcrypto_ed25519_hash_final(&hctx, prefix);
  memcpy(extsk + 32, prefix, 32);

  if (!bcrypto_ed25519_pubkey_tweak_add(tk, pk, tweak))
    return 0;

  return bcrypto_ed25519_sign_with_scalar(RS, m, mlen, extsk, tk, ph, ctx, ctx_len);
}

int
bcrypto_ed25519_sign_tweak_mul(
  bcrypto_ed25519_sig_t RS,
  const unsigned char *m,
  size_t mlen,
  const bcrypto_ed25519_privkey_t sk,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t tweak,
  int ph,
  const unsigned char *ctx,
  size_t ctx_len
) {
  hash_512bits extsk, prefix;
  bcrypto_ed25519_pubkey_t tk;
  bcrypto_ed25519_hash_t hctx;

  bcrypto_ed25519_extsk(extsk, sk);

  if (!bcrypto_ed25519_scalar_tweak_mul(extsk, extsk, tweak))
    return 0;

  bcrypto_ed25519_hash_init(&hctx);
  bcrypto_ed25519_hash_update(&hctx, extsk + 32, 32);
  bcrypto_ed25519_hash_update(&hctx, tweak, 32);
  bcrypto_ed25519_hash_final(&hctx, prefix);
  memcpy(extsk + 32, prefix, 32);

  if (!bcrypto_ed25519_pubkey_tweak_mul(tk, pk, tweak))
    return 0;

  return bcrypto_ed25519_sign_with_scalar(RS, m, mlen, extsk, tk, ph, ctx, ctx_len);
}

int
bcrypto_ed25519_pubkey_from_uniform(
  bcrypto_ed25519_pubkey_t out,
  const unsigned char bytes[32]
) {
  int sign = bcrypto_x25519_pubkey_from_uniform(out, bytes);

  if (sign < 0)
    return 0;

  return bcrypto_x25519_pubkey_convert(out, out, sign);
}

int
bcrypto_x25519_pubkey_from_uniform(
  bcrypto_x25519_pubkey_t out,
  const unsigned char bytes[32]
) {
  bignum25519 ALIGN(16) u, x1, x2;

  static const bignum25519 z = {2};
  static const bignum25519 a = {486662};
  bignum25519 e = {1};

  curve25519_expand(u, bytes);

  /* x1 = -a / (1 + z * u^2) */
  curve25519_square(x1, u);
  curve25519_mul(x1, x1, z);
  curve25519_add(x1, x1, e);
  curve25519_swap_conditional(x1, e, curve25519_is_zero(x1));
  curve25519_recip(x1, x1);
  curve25519_mul(x1, a, x1);
  curve25519_neg(x1, x1);

  /* x2 = -x1 - a */
  curve25519_neg(x2, x1);
  curve25519_sub(x2, x2, a);

  /* x = cmov(x1, x2, f(g(x1)) != 1) */
  curve25519_swap_conditional(x1, x2, curve25519_valid_x(x1) ^ 1);
  curve25519_contract(out, x1);

  return curve25519_is_odd(u);
}

int
bcrypto_ed25519_pubkey_to_uniform(
  unsigned char out[32],
  const bcrypto_ed25519_pubkey_t pub
) {
  int sign;

  if (!bcrypto_ed25519_pubkey_convert(out, &sign, pub))
    return 0;

  return bcrypto_x25519_pubkey_to_uniform(out, out, sign);
}

int
bcrypto_x25519_pubkey_to_uniform(
  unsigned char out[32],
  const bcrypto_x25519_pubkey_t pub,
  int sign
) {
  bignum25519 ALIGN(16) x, y, n, d, u;
  unsigned char bit = 0;
  int ret = 1;
  int lt;

  static const unsigned char fq2[32] = {
    0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f
  };

  static const bignum25519 z = {2};
  static const bignum25519 a = {486662};

  curve25519_expand(x, pub);

  /* recover y */
  ret &= curve25519_solve_y(y, x);
  curve25519_neg_conditional(y, y, curve25519_is_odd(y) ^ sign);

  /* check y < F(q / 2) */
  curve25519_contract(out, y);
  lt = curve25519_bytes_le(out, fq2);

  /* u = sqrt(-n / (d * z)) */
  curve25519_copy(n, x);
  curve25519_add(d, x, a);
  curve25519_swap_conditional(n, d, lt ^ 1);
  curve25519_neg(n, n);
  curve25519_mul(d, d, z);
  ret &= curve25519_isqrt(u, n, d);

  /* adjust sign */
  curve25519_neg_conditional(u, u, curve25519_is_odd(u) ^ sign);
  curve25519_contract(out, u);

  /* randomize the top bit */
  ret &= bcrypto_ed25519_randombytes(&bit, 1);

  out[31] |= (bit & 1) << 7;

  return ret;
}

int
bcrypto_ed25519_pubkey_from_hash(
  bcrypto_ed25519_pubkey_t out,
  const unsigned char bytes[64]
) {
  bcrypto_ed25519_pubkey_t k1, k2;
  ge25519 ALIGN(16) p1, p2;

  if (!bcrypto_ed25519_pubkey_from_uniform(k1, &bytes[0]))
    return 0;

  if (!bcrypto_ed25519_pubkey_from_uniform(k2, &bytes[32]))
    return 0;

  if (!ge25519_unpack(&p1, k1))
    return 0;

  if (!ge25519_unpack(&p2, k2))
    return 0;

  ge25519_add(&p1, &p1, &p2);
  ge25519_mulh(&p1, &p1);
  ge25519_pack(out, &p1);

  return 1;
}

int
bcrypto_x25519_pubkey_from_hash(
  bcrypto_x25519_pubkey_t out,
  const unsigned char bytes[64]
) {
  if (!bcrypto_ed25519_pubkey_from_hash(out, bytes))
    return 0;

  return bcrypto_ed25519_pubkey_convert(out, NULL, out);
}
