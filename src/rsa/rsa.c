#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "openssl/opensslv.h"
#include "rsa.h"

#if OPENSSL_VERSION_NUMBER >= 0x1010008fL

#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "openssl/objects.h"

void
bcrypto_rsa_key_init(bcrypto_rsa_key_t *key) {
  assert(key);
  memset((void *)key, 0x00, sizeof(bcrypto_rsa_key_t));
}

void
bcrypto_rsa_key_free(bcrypto_rsa_key_t *key) {
  assert(key);
  free((void *)key);
}

static RSA *
bcrypto_rsa_key2priv(const bcrypto_rsa_key_t *priv) {
  assert(priv);

  RSA *priv_r = NULL;
  BIGNUM *n = NULL;
  BIGNUM *e = NULL;
  BIGNUM *d = NULL;
  BIGNUM *p = NULL;
  BIGNUM *q = NULL;
  BIGNUM *dp = NULL;
  BIGNUM *dq = NULL;
  BIGNUM *qi = NULL;

  if (!priv
      || !priv->nd
      || !priv->ed
      || !priv->dd
      || !priv->pd
      || !priv->qd
      || !priv->dpd
      || !priv->dqd
      || !priv->qid) {
    goto fail;
  }

  priv_r = RSA_new();

  if (!priv_r)
    goto fail;

  n = BN_bin2bn(priv->nd, priv->nl, NULL);
  e = BN_bin2bn(priv->ed, priv->el, NULL);
  d = BN_bin2bn(priv->dd, priv->dl, NULL);
  p = BN_bin2bn(priv->pd, priv->pl, NULL);
  q = BN_bin2bn(priv->qd, priv->ql, NULL);
  dp = BN_bin2bn(priv->dpd, priv->dpl, NULL);
  dq = BN_bin2bn(priv->dqd, priv->dql, NULL);
  qi = BN_bin2bn(priv->qid, priv->qil, NULL);

  if (!n || !e || !d || !p || !q || !dp || !dq || !qi)
    goto fail;

  if (!RSA_set0_key(priv_r, n, e, d))
    goto fail;

  n = NULL;
  e = NULL;
  d = NULL;

  if (!RSA_set0_factors(priv_r, p, q))
    goto fail;

  p = NULL;
  q = NULL;

  if (!RSA_set0_crt_params(priv_r, dp, dq, qi))
    goto fail;

  return priv_r;

fail:
  if (priv_r)
    RSA_free(priv_r);

  if (n)
    BN_free(n);

  if (e)
    BN_free(e);

  if (d)
    BN_free(d);

  if (p)
    BN_free(p);

  if (q)
    BN_free(q);

  if (dp)
    BN_free(dp);

  if (dq)
    BN_free(dq);

  if (qi)
    BN_free(qi);

  return NULL;
}

static RSA *
bcrypto_rsa_key2pub(const bcrypto_rsa_key_t *pub) {
  assert(pub);

  RSA *pub_r = NULL;
  BIGNUM *n = NULL;
  BIGNUM *e = NULL;

  if (!pub
      || !pub->nd
      || !pub->ed) {
    goto fail;
  }

  pub_r = RSA_new();

  if (!pub_r)
    goto fail;

  n = BN_bin2bn(pub->nd, pub->nl, NULL);
  e = BN_bin2bn(pub->ed, pub->el, NULL);

  if (!n || !e)
    goto fail;

  if (!RSA_set0_key(pub_r, n, e, NULL))
    goto fail;

  return pub_r;

fail:
  if (pub_r)
    RSA_free(pub_r);

  if (n)
    BN_free(n);

  if (e)
    BN_free(e);

  return NULL;
}

static bcrypto_rsa_key_t *
bcrypto_rsa_priv2key(const RSA *priv_r) {
  assert(priv_r);

  uint8_t *arena = NULL;

  const BIGNUM *n = NULL;
  const BIGNUM *e = NULL;
  const BIGNUM *d = NULL;
  const BIGNUM *p = NULL;
  const BIGNUM *q = NULL;
  const BIGNUM *dp = NULL;
  const BIGNUM *dq = NULL;
  const BIGNUM *qi = NULL;

  RSA_get0_key(priv_r, &n, &e, &d);
  RSA_get0_factors(priv_r, &p, &q);
  RSA_get0_crt_params(priv_r, &dp, &dq, &qi);

  if (!n || !e || !d || !p || !q || !dp || !dq || !qi)
    goto fail;

  size_t nl = BN_num_bytes(n);
  size_t el = BN_num_bytes(e);
  size_t dl = BN_num_bytes(d);
  size_t pl = BN_num_bytes(p);
  size_t ql = BN_num_bytes(q);
  size_t dpl = BN_num_bytes(dp);
  size_t dql = BN_num_bytes(dq);
  size_t qil = BN_num_bytes(qi);

  size_t kl = sizeof(bcrypto_rsa_key_t);
  size_t size = kl + nl + el + dl + pl + ql + dpl + dql + qil;

  arena = malloc(size);

  if (!arena)
    goto fail;

  size_t pos = 0;

  bcrypto_rsa_key_t *priv;

  priv = (bcrypto_rsa_key_t *)&arena[pos];
  bcrypto_rsa_key_init(priv);
  pos += kl;

  priv->nd = (uint8_t *)&arena[pos];
  priv->nl = nl;
  pos += nl;

  priv->ed = (uint8_t *)&arena[pos];
  priv->el = el;
  pos += el;

  priv->dd = (uint8_t *)&arena[pos];
  priv->dl = dl;
  pos += dl;

  priv->pd = (uint8_t *)&arena[pos];
  priv->pl = pl;
  pos += pl;

  priv->qd = (uint8_t *)&arena[pos];
  priv->ql = ql;
  pos += ql;

  priv->dpd = (uint8_t *)&arena[pos];
  priv->dpl = dpl;
  pos += dpl;

  priv->dqd = (uint8_t *)&arena[pos];
  priv->dql = dql;
  pos += dql;

  priv->qid = (uint8_t *)&arena[pos];
  priv->qil = qil;
  pos += qil;

  assert(BN_bn2bin(n, priv->nd) != -1);
  assert(BN_bn2bin(e, priv->ed) != -1);
  assert(BN_bn2bin(d, priv->dd) != -1);
  assert(BN_bn2bin(p, priv->pd) != -1);
  assert(BN_bn2bin(q, priv->qd) != -1);
  assert(BN_bn2bin(dp, priv->dpd) != -1);
  assert(BN_bn2bin(dq, priv->dqd) != -1);
  assert(BN_bn2bin(qi, priv->qid) != -1);

  return priv;

fail:
  if (arena)
    free(arena);

  return NULL;
}

static bcrypto_rsa_key_t *
bcrypto_rsa_pub2key(const RSA *pub_r) {
  assert(pub_r);

  uint8_t *arena = NULL;

  const BIGNUM *n = NULL;
  const BIGNUM *e = NULL;

  RSA_get0_key(pub_r, &n, &e, NULL);

  if (!n || !e)
    goto fail;

  size_t nl = BN_num_bytes(n);
  size_t el = BN_num_bytes(e);

  size_t kl = sizeof(bcrypto_rsa_key_t);
  size_t size = kl + nl + el;

  arena = malloc(size);

  if (!arena)
    goto fail;

  size_t pos = 0;

  bcrypto_rsa_key_t *pub;

  pub = (bcrypto_rsa_key_t *)&arena[pos];
  bcrypto_rsa_key_init(pub);
  pos += kl;

  pub->nd = (uint8_t *)&arena[pos];
  pub->nl = nl;
  pos += nl;

  pub->ed = (uint8_t *)&arena[pos];
  pub->el = el;
  pos += el;

  assert(BN_bn2bin(n, pub->nd) != -1);
  assert(BN_bn2bin(e, pub->ed) != -1);

  return pub;

fail:
  if (arena)
    free(arena);

  return NULL;
}

static int
bcrypto_rsa_type(const char *alg) {
  if (alg == NULL)
    return -1;

  int type = -1;

  if (strcmp(alg, "md5") == 0)
    type = NID_md5;
  else if (strcmp(alg, "ripemd160") == 0)
    type = NID_ripemd160;
  else if (strcmp(alg, "sha1") == 0)
    type = NID_sha1;
  else if (strcmp(alg, "sha224") == 0)
    type = NID_sha224;
  else if (strcmp(alg, "sha256") == 0)
    type = NID_sha256;
  else if (strcmp(alg, "sha384") == 0)
    type = NID_sha384;
  else if (strcmp(alg, "sha512") == 0)
    type = NID_sha512;

#ifdef NID_blake2b160
  else if (strcmp(alg, "blake2b160") == 0)
    type = NID_blake2b160;
#endif

#ifdef NID_blake2b256
  else if (strcmp(alg, "blake2b") == 0)
    type = NID_blake2b256;
  else if (strcmp(alg, "blake2b256") == 0)
    type = NID_blake2b256;
#endif

#ifdef NID_blake2b512
  else if (strcmp(alg, "blake2b512") == 0)
    type = NID_blake2b512;
#endif

#ifdef NID_sha3_256
  else if (strcmp(alg, "keccak") == 0)
    type = NID_sha3_256;
  else if (strcmp(alg, "keccak256") == 0)
    type = NID_sha3_256;
  else if (strcmp(alg, "sha3") == 0)
    type = NID_sha3_256;
  else if (strcmp(alg, "sha3-256") == 0)
    type = NID_sha3_256;
#endif

#ifdef NID_sha3_384
  else if (strcmp(alg, "keccak384") == 0)
    type = NID_sha3_384;
  else if (strcmp(alg, "sha3-384") == 0)
    type = NID_sha3_384;
#endif

#ifdef NID_sha3_512
  else if (strcmp(alg, "keccak512") == 0)
    type = NID_sha3_512;
  else if (strcmp(alg, "sha3-512") == 0)
    type = NID_sha3_512;
#endif

  return type;
}

bcrypto_rsa_key_t *
bcrypto_rsa_generate(int bits, unsigned long long exp) {
  RSA *priv_r = NULL;
  BIGNUM *exp_bn = NULL;

  if (bits < 4)
    goto fail;

  if (exp < 3)
    goto fail;

  if ((exp & 1) == 0)
    goto fail;

  priv_r = RSA_new();

  if (!priv_r)
    goto fail;

  exp_bn = BN_new();

  if (!exp_bn)
    goto fail;

  if (!BN_set_word(exp_bn, (BN_ULONG)exp))
    goto fail;

  if (!RSA_generate_key_ex(priv_r, bits, exp_bn, NULL))
    goto fail;

  bcrypto_rsa_key_t *priv = bcrypto_rsa_priv2key(priv_r);

  if (!priv)
    goto fail;

  RSA_free(priv_r);
  BN_free(exp_bn);

  return priv;

fail:
  if (priv_r)
    RSA_free(priv_r);

  if (exp_bn)
    BN_free(exp_bn);

  return NULL;
}

bool
bcrypto_rsa_validate(const bcrypto_rsa_key_t *priv) {
  assert(priv);

  RSA *priv_r = NULL;

  priv_r = bcrypto_rsa_key2priv(priv);

  if (!priv_r)
    goto fail;

  if (RSA_check_key(priv_r) <= 0)
    goto fail;

  RSA_free(priv_r);

  return true;

fail:
  if (priv_r)
    RSA_free(priv_r);

  return false;
}

bool
bcrypto_rsa_compute(const bcrypto_rsa_key_t *priv, bcrypto_rsa_key_t **key) {
  assert(priv && key);

  bool ret = false;
  RSA *priv_r = NULL;
  BIGNUM *rsa_n = NULL;
  BIGNUM *rsa_e = NULL;
  BIGNUM *rsa_d = NULL;
  BIGNUM *rsa_p = NULL;
  BIGNUM *rsa_q = NULL;
  BIGNUM *rsa_dmp1 = NULL;
  BIGNUM *rsa_dmq1 = NULL;
  BIGNUM *rsa_iqmp = NULL;
  BN_CTX *ctx = NULL;
  BIGNUM *r0 = NULL;
  BIGNUM *r1 = NULL;
  BIGNUM *r2 = NULL;
  RSA *out_r = NULL;
  bcrypto_rsa_key_t *out = NULL;

  priv_r = bcrypto_rsa_key2priv(priv);

  if (!priv_r)
    goto fail;

  const BIGNUM *n = NULL;
  const BIGNUM *e = NULL;
  const BIGNUM *d = NULL;
  const BIGNUM *p = NULL;
  const BIGNUM *q = NULL;
  const BIGNUM *dp = NULL;
  const BIGNUM *dq = NULL;
  const BIGNUM *qi = NULL;

  RSA_get0_key(priv_r, &n, &e, &d);
  RSA_get0_factors(priv_r, &p, &q);
  RSA_get0_crt_params(priv_r, &dp, &dq, &qi);
  assert(n && e && d && p && q && dp && dq && qi);

  if (BN_is_zero(e) || BN_is_zero(p) || BN_is_zero(q))
    goto fail;

  if (!BN_is_zero(n)
      && !BN_is_zero(d)
      && !BN_is_zero(dp)
      && !BN_is_zero(dq)
      && !BN_is_zero(qi)) {
    *key = NULL;
    ret = true;
    goto fail;
  }

  int eb = BN_num_bits(e);
  int nb = BN_num_bits(p) + BN_num_bits(q);

  if (eb < 2 || eb > 33)
    goto fail;

  if (nb < 512 || nb > 16384)
    goto fail;

  if (!BN_is_odd(e))
    goto fail;

  rsa_n = BN_new();
  rsa_e = BN_new();
  rsa_d = BN_new();
  rsa_p = BN_new();
  rsa_q = BN_new();
  rsa_dmp1 = BN_new();
  rsa_dmq1 = BN_new();
  rsa_iqmp = BN_new();

  if (!rsa_n
      || !rsa_e
      || !rsa_d
      || !rsa_p
      || !rsa_q
      || !rsa_dmp1
      || !rsa_dmq1
      || !rsa_iqmp) {
    goto fail;
  }

  if (!BN_copy(rsa_n, n)
      || !BN_copy(rsa_e, e)
      || !BN_copy(rsa_d, d)
      || !BN_copy(rsa_p, p)
      || !BN_copy(rsa_q, q)
      || !BN_copy(rsa_dmp1, dp)
      || !BN_copy(rsa_dmq1, dq)
      || !BN_copy(rsa_iqmp, qi)) {
    goto fail;
  }

  ctx = BN_CTX_new();
  r0 = BN_new();
  r1 = BN_new();
  r2 = BN_new();

  if (!ctx || !r0 || !r1 || !r2)
    goto fail;

  // See: https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_gen.c

  if (BN_is_zero(rsa_n)) {
    // modulus n = p * q * r_3 * r_4
    if (!BN_mul(rsa_n, rsa_p, rsa_q, ctx))
      goto fail;
  }

  // p - 1
  if (!BN_sub(r1, rsa_p, BN_value_one()))
    goto fail;

  // q - 1
  if (!BN_sub(r2, rsa_q, BN_value_one()))
    goto fail;

  // (p - 1)(q - 1)
  if (!BN_mul(r0, r1, r2, ctx))
    goto fail;

  if (BN_is_zero(rsa_d)) {
    BIGNUM *pr0 = BN_new();

    if (pr0 == NULL)
      goto fail;

    BN_with_flags(pr0, r0, BN_FLG_CONSTTIME);

    if (!BN_mod_inverse(rsa_d, rsa_e, pr0, ctx)) {
      BN_free(pr0);
      goto fail;
    }

    BN_free(pr0);
  }

  if (BN_is_zero(rsa_dmp1) || BN_is_zero(rsa_dmq1)) {
    BIGNUM *d = BN_new();

    if (d == NULL)
      goto fail;

    BN_with_flags(d, rsa_d, BN_FLG_CONSTTIME);

    // calculate d mod (p-1) and d mod (q - 1)
    if (!BN_mod(rsa_dmp1, d, r1, ctx)
        || !BN_mod(rsa_dmq1, d, r2, ctx)) {
      BN_free(d);
      goto fail;
    }

    BN_free(d);
  }

  if (BN_is_zero(rsa_iqmp)) {
    BIGNUM *p = BN_new();

    if (p == NULL)
      goto fail;

    BN_with_flags(p, rsa_p, BN_FLG_CONSTTIME);

    // calculate inverse of q mod p
    if (!BN_mod_inverse(rsa_iqmp, rsa_q, p, ctx)) {
      BN_free(p);
      goto fail;
    }

    BN_free(p);
  }

  out_r = RSA_new();

  if (!out_r)
    goto fail;

  assert(RSA_set0_key(out_r, rsa_n, rsa_e, rsa_d));

  rsa_n = NULL;
  rsa_e = NULL;
  rsa_d = NULL;

  assert(RSA_set0_factors(out_r, rsa_p, rsa_q));

  rsa_p = NULL;
  rsa_q = NULL;

  assert(RSA_set0_crt_params(out_r, rsa_dmp1, rsa_dmq1, rsa_iqmp));

  rsa_dmp1 = NULL;
  rsa_dmq1 = NULL;
  rsa_iqmp = NULL;

  out = bcrypto_rsa_priv2key(out_r);

  if (!out)
    goto fail;

  RSA_free(priv_r);
  // BN_free(rsa_n);
  // BN_free(rsa_e);
  // BN_free(rsa_d);
  // BN_free(rsa_p);
  // BN_free(rsa_q);
  // BN_free(rsa_dmp1);
  // BN_free(rsa_dmq1);
  // BN_free(rsa_iqmp);
  BN_CTX_free(ctx);
  BN_free(r0);
  BN_free(r1);
  BN_free(r2);
  RSA_free(out_r);

  *key = out;

  return 1;

fail:
  if (priv_r)
    RSA_free(priv_r);

  if (rsa_n)
    BN_free(rsa_n);

  if (rsa_e)
    BN_free(rsa_e);

  if (rsa_d)
    BN_free(rsa_d);

  if (rsa_p)
    BN_free(rsa_p);

  if (rsa_q)
    BN_free(rsa_q);

  if (rsa_dmp1)
    BN_free(rsa_dmp1);

  if (rsa_dmq1)
    BN_free(rsa_dmq1);

  if (rsa_iqmp)
    BN_free(rsa_iqmp);

  if (ctx)
    BN_CTX_free(ctx);

  if (r0)
    BN_free(r0);

  if (r1)
    BN_free(r1);

  if (r2)
    BN_free(r2);

  if (out_r)
    RSA_free(out_r);

  return ret;
}

bool
bcrypto_rsa_sign(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  uint8_t **sig,
  size_t *sig_len
) {
  assert(priv && sig && sig_len);

  RSA *priv_r = NULL;
  uint8_t *sig_buf = NULL;
  size_t sig_buf_len = 0;

  int type = bcrypto_rsa_type(alg);

  if (type == -1)
    goto fail;

  priv_r = bcrypto_rsa_key2priv(priv);

  if (!priv_r)
    goto fail;

  sig_buf_len = RSA_size(priv_r);
  sig_buf = (uint8_t *)malloc(sig_buf_len * sizeof(uint8_t));

  if (!sig_buf)
    goto fail;

  // Protect against side-channel attacks.
  if (!RSA_blinding_on(priv_r, NULL))
    goto fail;

  int result = RSA_sign(
    type,
    msg,
    msg_len,
    sig_buf,
    (unsigned int *)&sig_buf_len,
    priv_r
  );

  RSA_blinding_off(priv_r);

  if (!result)
    goto fail;

  RSA_free(priv_r);

  *sig = sig_buf;
  *sig_len = sig_buf_len;

  return true;

fail:
  if (priv_r)
    RSA_free(priv_r);

  if (sig_buf)
    free(sig_buf);

  return false;
}

bool
bcrypto_rsa_verify(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *sig,
  size_t sig_len,
  const bcrypto_rsa_key_t *pub
) {
  assert(pub);

  RSA *pub_r = NULL;

  int type = bcrypto_rsa_type(alg);

  if (type == -1)
    goto fail;

  pub_r = bcrypto_rsa_key2pub(pub);

  if (!pub_r)
    goto fail;

  if (!RSA_verify(type, msg, msg_len, sig, sig_len, pub_r))
    goto fail;

  RSA_free(pub_r);

  return true;
fail:
  if (pub_r)
    RSA_free(pub_r);

  return false;
}

bool
bcrypto_rsa_encrypt(
  int type,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *pub,
  uint8_t **ct,
  size_t *ct_len
) {
  assert(pub && ct && ct_len);

  RSA *pub_r = NULL;
  uint8_t *out = NULL;

  pub_r = bcrypto_rsa_key2pub(pub);

  if (!pub_r)
    goto fail;

  int padding = type ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING;
  int max = type ? RSA_size(pub_r) - 41 : RSA_size(pub_r) - 11;

  if (max < 0 || msg_len > (size_t)max)
    goto fail;

  out = malloc(RSA_size(pub_r) * 2);

  if (!out)
    goto fail;

  int out_len = RSA_public_encrypt((int)msg_len, msg, out, pub_r, padding);

  if (out_len < 0)
    goto fail;

  RSA_free(pub_r);

  *ct = out;
  *ct_len = (size_t)out_len;

  return true;

fail:
  if (pub_r)
    RSA_free(pub_r);

  if (out)
    free(out);

  return false;
}

bool
bcrypto_rsa_decrypt(
  int type,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  uint8_t **pt,
  size_t *pt_len
) {
  assert(priv && pt && pt_len);

  RSA *priv_r = NULL;
  uint8_t *out = NULL;

  priv_r = bcrypto_rsa_key2priv(priv);

  if (!priv_r)
    goto fail;

  int padding = type ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING;

  out = malloc(RSA_size(priv_r));

  if (!out)
    goto fail;

  int out_len = RSA_private_decrypt((int)msg_len, msg, out, priv_r, padding);

  if (out_len < 0)
    goto fail;

  RSA_free(priv_r);

  *pt = out;
  *pt_len = (size_t)out_len;

  return true;

fail:
  if (priv_r)
    RSA_free(priv_r);

  if (out)
    free(out);

  return false;
}

#else

void
bcrypto_rsa_key_init(bcrypto_rsa_key_t *key) {}

void
bcrypto_rsa_key_free(bcrypto_rsa_key_t *key) {}

bcrypto_rsa_key_t *
bcrypto_rsa_generate(int bits, int exp) {
  return NULL;
}

bool
bcrypto_rsa_validate(const bcrypto_rsa_key_t *priv) {
  return false;
}

bool
bcrypto_rsa_compute(const bcrypto_rsa_key_t *priv, bcrypto_rsa_key_t **key) {
  return NULL;
}

bool
bcrypto_rsa_sign(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  uint8_t **sig,
  size_t *sig_len
) {
  return false;
}

bool
bcrypto_rsa_verify(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *sig,
  size_t sig_len,
  const bcrypto_rsa_key_t *pub
) {
  return false;
}

bool
bcrypto_rsa_encrypt(
  int type,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *pub,
  uint8_t **ct,
  size_t *ct_len
) {
  return false;
}

bool
bcrypto_rsa_decrypt(
  int type,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  uint8_t **pt,
  size_t *pt_len
) {
  return false;
}
#endif
