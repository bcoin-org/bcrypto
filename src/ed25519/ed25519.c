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

  if (!ge25519_pack_safe(pk, &A))
    return 0;

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
      || !ge25519_unpack_negative_vartime(&A, pk)) {
    return 0;
  }

  /* hram = H(R,A,m) */
  bcrypto_ed25519_hram(hash, ph, ctx, ctx_len, RS, pk, m, mlen);
  expand256_modm(hram, hash, 64);

  /* S */
  expand256_modm(S, RS + 32, 32);

  /* SB - H(R,A,m)A */
  ge25519_double_scalarmult_vartime(&R, &A, hram, S);

  if (!ge25519_pack_safe(checkR, &R))
    return 0;

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
      || !ge25519_unpack_negative_vartime(&A, pk)) {
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
  ge25519_double_scalarmult_vartime(&R, &A, hram, S);
  ge25519_pack(checkR, &R);

  /* check that Rh = ShB - H(R,A,m)Ah */
  return bcrypto_ed25519_equal(expectR, checkR, 32);
}

int
bcrypto_ed25519_pubkey_verify(const bcrypto_ed25519_pubkey_t pk) {
  ge25519 ALIGN(16) A;

  if (!ge25519_unpack_vartime(&A, pk))
    return 0;

  return 1;
}

/*
  Fast Curve25519 basepoint scalar multiplication
*/

void
bcrypto_x25519_pubkey_create(
  bcrypto_x25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t e
) {
  bcrypto_ed25519_scalar_t ec;
  bignum256modm s;
  bignum25519 ALIGN(16) yplusz, zminusy;
  ge25519 ALIGN(16) p;
  size_t i;

  /* clamp */
  for (i = 0; i < 32; i++)
    ec[i] = e[i];

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
  const bcrypto_ed25519_pubkey_t pk
) {
  bignum25519 ALIGN(16) yplusz, zminusy;
  ge25519 ALIGN(16) p;

  /* ed25519 pubkey -> ed25519 point */
  if (!ge25519_unpack_vartime(&p, pk))
    return 0;

  /* ed25519 point -> x25519 point */
  curve25519_add(yplusz, p.y, p.z);
  curve25519_sub(zminusy, p.z, p.y);

  // P = (x, 1) = O
  if (curve25519_is_zero(zminusy))
    return 0;

  // P = (0, y) = (0, 0)
  if (curve25519_is_zero(p.x)) {
    memset(out, 0x00, 32);
    return 1;
  }

  curve25519_recip(zminusy, zminusy);
  curve25519_mul(yplusz, yplusz, zminusy);

  /* output point (little-endian u coord) */
  curve25519_contract(out, yplusz);

  return 1;
}

int
bcrypto_ed25519_pubkey_deconvert(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_x25519_pubkey_t pk,
  int sign
) {
  bignum25519 ALIGN(16) x, z, xminusz, xplusz;

  curve25519_expand(x, pk);
  curve25519_set_word(z, 1);
  curve25519_sub(xminusz, x, z);
  curve25519_add(xplusz, x, z);

  // P = (-1, v) = O
  if (curve25519_is_zero(xplusz))
    return 0;

  curve25519_recip(xplusz, xplusz);
  curve25519_mul(x, xminusz, xplusz);

  curve25519_contract(out, x);

  if (sign)
    out[31] |= 0x80;

  return 1;
}

int
bcrypto_ed25519_derive_with_scalar(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk,
  const bcrypto_ed25519_scalar_t sk
) {
  bignum256modm k;
  ge25519 ALIGN(16) s, p;
  bcrypto_ed25519_scalar_t ec;
  size_t i;

  /* clamp */
  for (i = 0; i < 32; i++)
    ec[i] = sk[i];

  ec[0] &= 248;
  ec[31] &= 127;
  ec[31] |= 64;

  expand_raw256_modm(k, ec);

  if (!ge25519_unpack_vartime(&p, pk))
    return 0;

  ge25519_scalarmult_vartime(&s, &p, k);

  if (!ge25519_pack_safe(out, &s))
    return 0;

  return 1;
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
bcrypto_ed25519_exchange_with_scalar(
  bcrypto_x25519_pubkey_t out,
  const bcrypto_x25519_pubkey_t xpk,
  const bcrypto_ed25519_scalar_t sk
) {
  bcrypto_ed25519_scalar_t k;
  bignum25519 ALIGN(16) nd, x1, x2, z2, x3, z3, t1, t2;
  unsigned char zero[32];

  int swap = 0;
  size_t i;
  int t, b;

  /* clamp */
  for (i = 0; i < 32; i++)
    k[i] = sk[i];

  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;

  memset(&zero[0], 0, 32);

  curve25519_set_word(nd, 121666);

  curve25519_expand(x1, xpk);
  curve25519_set_word(x2, 1);
  curve25519_set_word(z2, 0);
  curve25519_copy(x3, x1);
  curve25519_set_word(z3, 1);

  for (t = 255 - 1; t >= 0; t--) {
    b = (k[t >> 3] >> (t & 7)) & 1;

    swap ^= b;

    curve25519_swap_conditional(x2, x3, swap);
    curve25519_swap_conditional(z2, z3, swap);

    swap = b;

    curve25519_sub(t1, x3, z3);
    curve25519_sub(t2, x2, z2);
    curve25519_add(x2, x2, z2);
    curve25519_add(z2, x3, z3);
    curve25519_mul(z3, t1, x2);
    curve25519_mul(z2, z2, t2);
    curve25519_square(t1, t2);
    curve25519_square(t2, x2);
    curve25519_add(x3, z3, z2);
    curve25519_sub(z2, z3, z2);
    curve25519_mul(x2, t2, t1);
    curve25519_sub(t2, t2, t1);
    curve25519_square(z2, z2);
    curve25519_mul(z3, t2, nd);
    curve25519_square(x3, x3);
    curve25519_add(t1, t1, z3);
    curve25519_mul(z3, x1, z2);
    curve25519_mul(z2, t2, t1);
  }

  /* Finish. */
  curve25519_swap_conditional(x2, x3, swap);
  curve25519_swap_conditional(z2, z3, swap);

  curve25519_recip(z2, z2);
  curve25519_mul(x1, x2, z2);

  curve25519_contract(out, x1);

  return bcrypto_ed25519_equal(out, &zero[0], 32) ^ 1;
}

int
bcrypto_ed25519_exchange(
  bcrypto_x25519_pubkey_t out,
  const bcrypto_x25519_pubkey_t xpk,
  const bcrypto_ed25519_privkey_t sk
) {
  hash_512bits extsk;
  bcrypto_ed25519_extsk(extsk, sk);
  return bcrypto_ed25519_exchange_with_scalar(out, xpk, extsk);
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

  if (iszero256_modm_batch(k))
    return 0;

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

  if (iszero256_modm_batch(k))
    return 0;

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

  if (iszero256_modm_batch(k))
    return 0;

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

  if (!ge25519_unpack_vartime(&k, pk))
    return 0;

  expand256_modm(t, tweak, 32);

  ge25519_scalarmult_base_niels(&T, ge25519_niels_base_multiples, t);

  ge25519_add(&k, &k, &T);

  if (!ge25519_pack_safe(out, &k))
    return 0;

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

  if (!ge25519_unpack_vartime(&k, pk))
    return 0;

  expand_raw256_modm(t, tweak);

  ge25519_scalarmult_vartime(&T, &k, t);

  if (!ge25519_pack_safe(out, &T))
    return 0;

  return 1;
}

int
bcrypto_ed25519_pubkey_add(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk1,
  const bcrypto_ed25519_pubkey_t pk2
) {
  ge25519 ALIGN(16) k1, k2;

  if (!ge25519_unpack_vartime(&k1, pk1))
    return 0;

  if (!ge25519_unpack_vartime(&k2, pk2))
    return 0;

  ge25519_add(&k1, &k1, &k2);

  if (!ge25519_pack_safe(out, &k1))
    return 0;

  return 1;
}

int
bcrypto_ed25519_pubkey_combine(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t *pks,
  size_t length
) {
  ge25519 ALIGN(16) k1, k2;
  size_t i = 1;

  if (length == 0)
    return 0;

  if (!ge25519_unpack_vartime(&k1, pks[0]))
    return 0;

  for (; i < length; i++) {
    if (!ge25519_unpack_vartime(&k2, pks[i]))
      return 0;

    ge25519_add(&k1, &k1, &k2);
  }

  if (!ge25519_pack_safe(out, &k1))
    return 0;

  return 1;
}

int
bcrypto_ed25519_pubkey_negate(
  bcrypto_ed25519_pubkey_t out,
  const bcrypto_ed25519_pubkey_t pk
) {
  ge25519 ALIGN(16) k;

  if (!ge25519_unpack_vartime(&k, pk))
    return 0;

  ge25519_neg(&k, &k);

  if (!ge25519_pack_safe(out, &k))
    return 0;

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

  if (!ge25519_pack_safe(RS, &R))
    return 0;

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
  int sign = bcrypto_ed25519_point_from_uniform(out, bytes);

  if (sign < 0)
    return 0;

  return bcrypto_ed25519_pubkey_deconvert(out, out, sign);
}

int
bcrypto_ed25519_point_from_uniform(
  bcrypto_x25519_pubkey_t out,
  const unsigned char bytes[32]
) {
  bignum25519 ALIGN(16) one, u, r, a, i2;
  bignum25519 ALIGN(16) v, v2, v3, e, l, x;

  /*
   * f(a) = a^((q - 1) / 2)
   * v = -A / (1 + u * r^2)
   * e = f(v^3 + A * v^2 + B * v)
   * x = e * v - (1 - e) * A / 2
   * y = -e * sqrt(x^3 + A * x^2 + B * x)
   */

  curve25519_set_word(one, 1);
  curve25519_set_word(e, 1);
  curve25519_set_word(u, 2);
  curve25519_set_word(a, 486662);
  curve25519_set_word(i2, 2);
  curve25519_recip(i2, i2);

  curve25519_expand(r, bytes);

  /* v = -a / (1 + u * r^2) */
  curve25519_square(v, r);
  curve25519_mul(v, v, u);
  curve25519_add(v, v, one);
  curve25519_swap_conditional(v, e, curve25519_is_zero(v));
  curve25519_recip(v, v);
  curve25519_neg(a, a);
  curve25519_mul(v, a, v);
  curve25519_neg(a, a);

  curve25519_square(v2, v);
  curve25519_mul(v3, v2, v);

  /* e = (v^3 + a * v^2 + v)^((p - 1) / 2) */
  curve25519_mul(e, a, v2);
  curve25519_add(e, e, v3);
  curve25519_add(e, e, v);
  curve25519_pow_two255m20d2(e, e);

  /* l = (1 - e) * a / 2 */
  curve25519_sub(l, one, e);
  curve25519_mul(l, l, a);
  curve25519_mul(l, l, i2);

  /* x = e * v - l */
  curve25519_mul(x, e, v);
  curve25519_sub(x, x, l);

  curve25519_contract(out, x);

  return curve25519_is_odd(r);
}

int
bcrypto_ed25519_pubkey_to_uniform(
  unsigned char out[32],
  const bcrypto_ed25519_pubkey_t pub
) {
  int sign = (pub[31] & 0x80) != 0;
  int i;

  for (i = 0; i < 32; i++)
    out[i] = 0;

  return bcrypto_ed25519_pubkey_convert(out, pub)
       & bcrypto_ed25519_point_to_uniform(out, out, sign);
}

int
bcrypto_ed25519_point_to_uniform(
  unsigned char out[32],
  const bcrypto_x25519_pubkey_t pub,
  int sign
) {
  bignum25519 ALIGN(16) u, a;
  bignum25519 ALIGN(16) x, y, n, d, r;
  int ret = 1;

  static const unsigned char fq2[32] = {
    0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f
  };

  /*
   * r = sqrt(-x / ((x + A) * u)) if y is in F(q / 2)
   *   = sqrt(-(x + A) / (u * x)) otherwise
   */

  curve25519_set_word(u, 2);
  curve25519_set_word(a, 486662);

  curve25519_expand(x, pub);

  /* y^2 = x^3 + a * x^2 + x */
  {
    bignum25519 ALIGN(16) x2, x3, y2;

    curve25519_square(x2, x);
    curve25519_mul(x3, x2, x);
    curve25519_add(y2, x3, x);
    curve25519_mul(x3, x2, a);
    curve25519_add(y2, y2, x3);

    ret &= curve25519_sqrt(y, y2);

    curve25519_cond_neg(y, y, curve25519_is_odd(y) ^ sign);
  }

  curve25519_contract(out, y);

  int gte = curve25519_bytes_le(out, fq2) ^ 1;

  curve25519_copy(n, x);
  curve25519_add(d, x, a);
  curve25519_swap_conditional(n, d, gte);
  curve25519_neg(n, n);
  curve25519_mul(d, d, u);
  curve25519_recip(d, d);

  ret &= curve25519_is_zero(d) ^ 1;

  curve25519_mul(r, n, d);

  ret &= curve25519_sqrt(r, r);

  curve25519_cond_neg(r, r, curve25519_is_odd(r) ^ sign);
  curve25519_contract(out, r);

  unsigned char bit = 0;

  ret &= bcrypto_ed25519_randombytes(&bit, 1);

  out[31] |= (bit & 1) << 7;

  return ret;
}
