#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "openssl/opensslv.h"
#include "dsa.h"

#if OPENSSL_VERSION_NUMBER >= 0x1010008fL

#include "openssl/bn.h"
#include "openssl/dsa.h"
#include "openssl/objects.h"

void
bcrypto_dsa_key_init(bcrypto_dsa_key_t *key) {
  assert(key);
  memset((void *)key, 0x00, sizeof(bcrypto_dsa_key_t));
}

void
bcrypto_dsa_key_free(bcrypto_dsa_key_t *key) {
  assert(key);
  free((void *)key);
}

static DSA *
bcrypto_dsa_key2dsa(const bcrypto_dsa_key_t *key, int mode) {
  assert(key);

  DSA *key_d = NULL;
  BIGNUM *p = NULL;
  BIGNUM *q = NULL;
  BIGNUM *g = NULL;
  BIGNUM *y = NULL;
  BIGNUM *x = NULL;

  if (!key
      || !key->pd
      || !key->qd
      || !key->gd
      || (mode > 0 && !key->yd)
      || (mode == 2 && !key->xd)) {
    goto fail;
  }

  key_d = DSA_new();

  if (!key_d)
    goto fail;

  p = BN_bin2bn(key->pd, key->pl, NULL);
  q = BN_bin2bn(key->qd, key->ql, NULL);
  g = BN_bin2bn(key->gd, key->gl, NULL);

  if (mode > 0)
    y = BN_bin2bn(key->yd, key->yl, NULL);

  if (mode == 2)
    x = BN_bin2bn(key->xd, key->xl, NULL);

  if (!p || !q || !g || (mode > 0 && !y) || (mode == 2 && !x))
    goto fail;

  if (!DSA_set0_pqg(key_d, p, q, g))
    goto fail;

  p = NULL;
  q = NULL;
  g = NULL;

  if (mode > 0) {
    if (!DSA_set0_key(key_d, y, x))
      goto fail;
  }

  y = NULL;
  x = NULL;

  return key_d;

fail:
  if (key_d)
    DSA_free(key_d);

  if (p)
    BN_free(p);

  if (q)
    BN_free(q);

  if (g)
    BN_free(g);

  if (y)
    BN_free(y);

  if (x)
    BN_free(x);

  return NULL;
}

static DSA *
bcrypto_dsa_key2params(const bcrypto_dsa_key_t *params) {
  return bcrypto_dsa_key2dsa(params, 0);
}

static DSA *
bcrypto_dsa_key2pub(const bcrypto_dsa_key_t *pub) {
  return bcrypto_dsa_key2dsa(pub, 1);
}

static DSA *
bcrypto_dsa_key2priv(const bcrypto_dsa_key_t *priv) {
  return bcrypto_dsa_key2dsa(priv, 2);
}

static bcrypto_dsa_key_t *
bcrypto_dsa_dsa2key(const DSA *key_d, int mode) {
  assert(key_d);

  uint8_t *arena = NULL;

  const BIGNUM *p = NULL;
  const BIGNUM *q = NULL;
  const BIGNUM *g = NULL;
  const BIGNUM *y = NULL;
  const BIGNUM *x = NULL;

  DSA_get0_pqg(key_d, &p, &q, &g);

  if (mode > 0)
    DSA_get0_key(key_d, &y, mode == 2 ? &x : NULL);

  if (!p || !q || !g || (mode > 0 && !y) || (mode == 2 && !x))
    goto fail;

  size_t pl = BN_num_bytes(p);
  size_t ql = BN_num_bytes(q);
  size_t gl = BN_num_bytes(g);
  size_t yl = mode > 0 ? BN_num_bytes(y) : 0;
  size_t xl = mode == 2 ? BN_num_bytes(x) : 0;

  size_t kl = sizeof(bcrypto_dsa_key_t);
  size_t size = kl + pl + ql + gl + yl + xl;

  arena = malloc(size);

  if (!arena)
    goto fail;

  size_t pos = 0;

  bcrypto_dsa_key_t *key;

  key = (bcrypto_dsa_key_t *)&arena[pos];
  bcrypto_dsa_key_init(key);
  pos += kl;

  key->pd = (uint8_t *)&arena[pos];
  key->pl = pl;
  pos += pl;

  key->qd = (uint8_t *)&arena[pos];
  key->ql = ql;
  pos += ql;

  key->gd = (uint8_t *)&arena[pos];
  key->gl = gl;
  pos += gl;

  if (mode > 0) {
    key->yd = (uint8_t *)&arena[pos];
    key->yl = yl;
    pos += yl;
  }

  if (mode == 2) {
    key->xd = (uint8_t *)&arena[pos];
    key->xl = xl;
    pos += xl;
  }

  assert(BN_bn2bin(p, key->pd) != -1);
  assert(BN_bn2bin(q, key->qd) != -1);
  assert(BN_bn2bin(g, key->gd) != -1);

  if (mode > 0)
    assert(BN_bn2bin(y, key->yd) != -1);

  if (mode == 2)
    assert(BN_bn2bin(x, key->xd) != -1);

  return key;

fail:
  if (arena)
    free(arena);

  return NULL;
}

static bcrypto_dsa_key_t *
bcrypto_dsa_params2key(const DSA *params_d) {
  return bcrypto_dsa_dsa2key(params_d, 0);
}

static bcrypto_dsa_key_t *
bcrypto_dsa_pub2key(const DSA *pub_d) {
  return bcrypto_dsa_dsa2key(pub_d, 1);
}

static bcrypto_dsa_key_t *
bcrypto_dsa_priv2key(const DSA *priv_d) {
  return bcrypto_dsa_dsa2key(priv_d, 2);
}

static DSA_SIG *
bcrypto_dsa_rs2sig(
  const uint8_t *r,
  size_t r_len,
  const uint8_t *s,
  size_t s_len
) {
  DSA_SIG *sig_d = NULL;
  BIGNUM *r_bn = NULL;
  BIGNUM *s_bn = NULL;

  sig_d = DSA_SIG_new();

  if (!sig_d)
    goto fail;

  r_bn = BN_bin2bn(r, r_len, NULL);

  if (!r_bn)
    goto fail;

  s_bn = BN_bin2bn(s, s_len, NULL);

  if (!s_bn)
    goto fail;

  if (!DSA_SIG_set0(sig_d, r_bn, s_bn))
    goto fail;

  return sig_d;

fail:
  if (sig_d)
    DSA_SIG_free(sig_d);

  if (r_bn)
    BN_free(r_bn);

  if (s_bn)
    BN_free(s_bn);

  return NULL;
}

static bool
bcrypto_dsa_sig2rs(
  const DSA *priv_d,
  const DSA_SIG *sig_d,
  uint8_t **r,
  uint8_t **s
) {
  uint8_t *r_buf = NULL;
  uint8_t *s_buf = NULL;

  const BIGNUM *r_bn;
  const BIGNUM *s_bn;

  DSA_SIG_get0(sig_d, &r_bn, &s_bn);
  assert(r_bn && s_bn);

  const BIGNUM *q_bn;

  DSA_get0_pqg(priv_d, NULL, &q_bn, NULL);
  assert(q_bn);

  int bits = BN_num_bits(q_bn);
  size_t size = (bits + 7) / 8;

  assert((size_t)BN_num_bytes(r_bn) <= size);
  assert((size_t)BN_num_bytes(s_bn) <= size);

  r_buf = malloc(size);
  s_buf = malloc(size);

  if (!r_buf || !s_buf)
    goto fail;

  assert(BN_bn2binpad(r_bn, r_buf, size) > 0);
  assert(BN_bn2binpad(s_bn, s_buf, size) > 0);

  *r = r_buf;
  *s = s_buf;

  return true;

fail:
  if (r_buf)
    free(r_buf);

  if (s_buf)
    free(s_buf);

  return false;
}

bcrypto_dsa_key_t *
bcrypto_dsa_generate_params(int bits) {
  DSA *params_d = NULL;

  params_d = DSA_new();

  if (!params_d)
    goto fail;

  if (!DSA_generate_parameters_ex(params_d, bits, NULL, 0, NULL, NULL, NULL))
    goto fail;

  bcrypto_dsa_key_t *params = bcrypto_dsa_params2key(params_d);

  if (!params)
    goto fail;

  DSA_free(params_d);

  return params;

fail:
  if (params_d)
    DSA_free(params_d);

  return NULL;
}

bcrypto_dsa_key_t *
bcrypto_dsa_generate(bcrypto_dsa_key_t *params) {
  assert(params);

  DSA *priv_d = NULL;

  priv_d = bcrypto_dsa_key2params(params);

  if (!priv_d)
    goto fail;

  if (!DSA_generate_key(priv_d))
    goto fail;

  bcrypto_dsa_key_t *priv = bcrypto_dsa_priv2key(priv_d);

  if (!priv)
    goto fail;

  DSA_free(priv_d);

  return priv;

fail:
  if (priv_d)
    DSA_free(priv_d);

  return NULL;
}

bool
bcrypto_dsa_compute(
  bcrypto_dsa_key_t *priv,
  uint8_t **out,
  size_t *out_len
) {
  if (!priv || !priv->pd || !priv->gd || !priv->xd)
    return false;

  BN_CTX *ctx = NULL;
  BIGNUM *p_bn = NULL;
  BIGNUM *g_bn = NULL;
  BIGNUM *y_bn = NULL;
  BIGNUM *x_bn = NULL;
  BIGNUM *prk_bn = NULL;
  size_t y_len;
  uint8_t *y_buf = NULL;

  ctx = BN_CTX_new();
  p_bn = BN_bin2bn(priv->pd, priv->pl, NULL);
  g_bn = BN_bin2bn(priv->gd, priv->gl, NULL);
  y_bn = BN_new();
  x_bn = BN_bin2bn(priv->xd, priv->xl, NULL);
  prk_bn = BN_new();

  if (!ctx || !p_bn || !g_bn || !y_bn || !x_bn || !prk_bn)
    goto fail;

  BN_with_flags(prk_bn, x_bn, BN_FLG_CONSTTIME);

  if (!BN_mod_exp(y_bn, g_bn, prk_bn, p_bn, ctx))
    goto fail;

  y_len = BN_num_bytes(y_bn);
  y_buf = malloc(y_len);

  if (!y_buf)
    goto fail;

  assert(BN_bn2bin(y_bn, y_buf) != -1);

  BN_CTX_free(ctx);
  BN_free(p_bn);
  BN_free(g_bn);
  BN_free(y_bn);
  BN_free(x_bn);
  BN_free(prk_bn);

  *out = y_buf;
  *out_len = y_len;

  return true;

fail:
  if (ctx)
    BN_CTX_free(ctx);

  if (p_bn)
    BN_free(p_bn);

  if (g_bn)
    BN_free(g_bn);

  if (y_bn)
    BN_free(y_bn);

  if (x_bn)
    BN_free(x_bn);

  if (prk_bn)
    BN_free(prk_bn);

  return false;
}

bool
bcrypto_dsa_sign(
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_dsa_key_t *priv,
  uint8_t **r,
  size_t *r_len,
  uint8_t **s,
  size_t *s_len
) {
  DSA *priv_d = NULL;
  DSA_SIG *sig_d = NULL;

  priv_d = bcrypto_dsa_key2priv(priv);

  if (!priv_d)
    goto fail;

  sig_d = DSA_do_sign(msg, msg_len, priv_d);

  if (!sig_d)
    goto fail;

  if (!bcrypto_dsa_sig2rs(priv_d, sig_d, r, s))
    goto fail;

  const BIGNUM *q_bn;

  DSA_get0_pqg(priv_d, NULL, &q_bn, NULL);
  assert(q_bn);

  int bits = BN_num_bits(q_bn);
  size_t size = (bits + 7) / 8;

  *r_len = size;
  *s_len = size;

  DSA_free(priv_d);
  DSA_SIG_free(sig_d);

  return true;

fail:
  if (priv_d)
    DSA_free(priv_d);

  if (sig_d)
    DSA_SIG_free(sig_d);

  return false;
}

bool
bcrypto_dsa_verify(
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *r,
  size_t r_len,
  const uint8_t *s,
  size_t s_len,
  const bcrypto_dsa_key_t *pub
) {
  DSA *pub_d = NULL;
  DSA_SIG *sig_d = NULL;

  pub_d = bcrypto_dsa_key2pub(pub);

  if (!pub_d)
    goto fail;

  sig_d = bcrypto_dsa_rs2sig(r, r_len, s, s_len);

  if (!sig_d)
    goto fail;

  if (DSA_do_verify(msg, msg_len, sig_d, pub_d) <= 0)
    goto fail;

  DSA_free(pub_d);
  DSA_SIG_free(sig_d);

  return true;

fail:
  if (pub_d)
    DSA_free(pub_d);

  if (sig_d)
    DSA_SIG_free(sig_d);

  return false;
}

#else

void
bcrypto_dsa_key_init(bcrypto_dsa_key_t *key) {}

void
bcrypto_dsa_key_free(bcrypto_dsa_key_t *key) {}

bcrypto_dsa_key_t *
bcrypto_dsa_generate_params(int bits) {
  return NULL;
}

bcrypto_dsa_key_t *
bcrypto_dsa_generate(bcrypto_dsa_key_t *params) {
  return NULL;
}

bool
bcrypto_dsa_compute(
  bcrypto_dsa_key_t *priv,
  uint8_t **out,
  size_t *out_len
) {
  return false;
}

bool
bcrypto_dsa_sign(
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_dsa_key_t *priv,
  uint8_t **r,
  size_t *r_len,
  uint8_t **s,
  size_t *s_len
) {
  return false;
}

bool
bcrypto_dsa_verify(
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *r,
  size_t r_len,
  const uint8_t *s,
  size_t s_len,
  const bcrypto_dsa_key_t *pub
) {
  return false;
}

#endif
