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
bcrypto_rsa_generate(int bits, int exp) {
  RSA *priv_r = NULL;
  BIGNUM *exp_bn = NULL;

  if (bits < 0 || bits > 8192)
    goto fail;

  if (exp < 0)
    goto fail;

  if (exp == 0)
    exp = 0x010001;

  priv_r = RSA_new();

  if (!priv_r)
    goto fail;

  exp_bn = BN_new();

  if (!exp_bn)
    goto fail;

  if (!BN_set_word(exp_bn, exp))
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

  return false;
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
bcrypto_rsa_verify_priv(const bcrypto_rsa_key_t *priv) {
  assert(priv);

  RSA *priv_r = NULL;

  priv_r = bcrypto_rsa_key2priv(priv);

  if (!priv_r)
    goto fail;

  if (!RSA_check_key(priv_r))
    goto fail;

  RSA_free(priv_r);

  return true;

fail:
  if (priv_r)
    RSA_free(priv_r);

  return false;
}

bool
bcrypto_rsa_verify_pub(const bcrypto_rsa_key_t *pub) {
  assert(pub);
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
bcrypto_rsa_verify_priv(const bcrypto_rsa_key_t *priv) {
  return false;
}

bool
bcrypto_rsa_verify_pub(const bcrypto_rsa_key_t *pub) {
  return false;
}

#endif
