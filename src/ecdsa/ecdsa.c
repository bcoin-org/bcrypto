#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "openssl/opensslv.h"
#include "ecdsa.h"

#if OPENSSL_VERSION_NUMBER >= 0x1010008fL

#include "openssl/ecdsa.h"
#include "openssl/objects.h"

// https://github.com/openssl/openssl/blob/master/include/openssl/bn.h
// https://github.com/openssl/openssl/blob/master/include/openssl/ec.h
// https://github.com/openssl/openssl/tree/master/crypto/bn
// https://github.com/openssl/openssl/tree/master/crypto/ec
// https://github.com/openssl/openssl/blob/master/crypto/ec/ec_key.c
// https://github.com/openssl/openssl/blob/master/crypto/ec/ec_oct.c
// https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography
// https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman

static int
bcrypto_ecdsa_curve(const char *name) {
  int type = -1;

  if (strcmp(name, "p192") == 0)
    type = NID_X9_62_prime192v1;
  else if (strcmp(name, "p224") == 0)
    type = NID_secp224r1;
  else if (strcmp(name, "p256") == 0)
    type = NID_X9_62_prime256v1;
  else if (strcmp(name, "p384") == 0)
    type = NID_secp384r1;
  else if (strcmp(name, "p521") == 0)
    type = NID_secp521r1;
  else if (strcmp(name, "secp256k1") == 0)
    type = NID_secp256k1;
#ifdef NID_curve25519
  else if (strcmp(name, "curve25519") == 0)
    type = NID_curve25519;
#endif

  return type;
}

static BIGNUM *
bcrypto_ecdsa_order(const char *name, size_t *size) {
  BN_CTX *ctx = NULL;
  EC_KEY *key_ec = NULL;
  BIGNUM *order_bn = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  // We need the group, and I have no
  // idea how to easily get it by nid
  // other than allocating a key!
  key_ec = EC_KEY_new_by_curve_name(type);

  if (!key_ec)
    goto fail;

  const EC_GROUP *group = EC_KEY_get0_group(key_ec);
  assert(group);

  order_bn = BN_new();

  if (!order_bn)
    goto fail;

  if (!EC_GROUP_get_order(group, order_bn, ctx))
    goto fail;

  if (size) {
    int field_size = EC_GROUP_get_degree(group);
    *size = (field_size + 7) / 8;
  }

  EC_KEY_free(key_ec);
  BN_CTX_free(ctx);

  return order_bn;

fail:
  if (key_ec)
    EC_KEY_free(key_ec);

  if (order_bn)
    BN_free(order_bn);

  if (ctx)
    BN_CTX_free(ctx);

  return NULL;
}

static ECDSA_SIG *
bcrypto_ecdsa_rs2sig(
  const uint8_t *r,
  size_t r_len,
  const uint8_t *s,
  size_t s_len
) {
  ECDSA_SIG *sig_ec = NULL;
  BIGNUM *r_bn = NULL;
  BIGNUM *s_bn = NULL;

  sig_ec = ECDSA_SIG_new();

  if (!sig_ec)
    goto fail;

  r_bn = BN_bin2bn(r, r_len, NULL);

  if (!r_bn)
    goto fail;

  s_bn = BN_bin2bn(s, s_len, NULL);

  if (!s_bn)
    goto fail;

  if (!ECDSA_SIG_set0(sig_ec, r_bn, s_bn))
    goto fail;

  return sig_ec;

fail:
  if (sig_ec)
    ECDSA_SIG_free(sig_ec);

  if (r_bn)
    BN_free(r_bn);

  if (s_bn)
    BN_free(s_bn);

  return NULL;
}

static bool
bcrypto_ecdsa_sig2rs(
  const EC_GROUP *group,
  const ECDSA_SIG *sig_ec,
  uint8_t **r,
  uint8_t **s
) {
  BN_CTX *ctx = NULL;
  uint8_t *r_buf = NULL;
  uint8_t *s_buf = NULL;
  BIGNUM *order_bn = NULL;
  BIGNUM *half_bn = NULL;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  const BIGNUM *r_bn;
  const BIGNUM *s_bn;

  ECDSA_SIG_get0(sig_ec, &r_bn, &s_bn);
  assert(r_bn && s_bn);

  order_bn = BN_new();
  half_bn = BN_new();

  if (!order_bn || !half_bn)
    goto fail;

  if (!EC_GROUP_get_order(group, order_bn, ctx))
    goto fail;

  if (!BN_rshift1(half_bn, order_bn))
    goto fail;

  if (BN_cmp(s_bn, half_bn) > 0) {
    if (!BN_sub(order_bn, order_bn, s_bn))
      goto fail;
    s_bn = (const BIGNUM *)order_bn;
  }

  int bits = EC_GROUP_get_degree(group);
  size_t size = (bits + 7) / 8;

  assert((size_t)BN_num_bytes(r_bn) <= size);
  assert((size_t)BN_num_bytes(s_bn) <= size);

  r_buf = malloc(size);
  s_buf = malloc(size);

  if (!r_buf || !s_buf)
    goto fail;

  assert(BN_bn2binpad(r_bn, r_buf, size) > 0);
  assert(BN_bn2binpad(s_bn, s_buf, size) > 0);

  BN_free(order_bn);
  BN_free(half_bn);
  BN_CTX_free(ctx);

  *r = r_buf;
  *s = s_buf;

  return true;

fail:
  if (order_bn)
    BN_free(order_bn);

  if (half_bn)
    BN_free(half_bn);

  if (ctx)
    BN_CTX_free(ctx);

  if (r_buf)
    free(r_buf);

  if (s_buf)
    free(s_buf);

  return false;
}

// Note: could do this in js-land by
// hard-coding all the orders.
bool
bcrypto_ecdsa_generate(const char *name, uint8_t **priv, size_t *priv_len) {
  EC_KEY *priv_ec = NULL;
  uint8_t *priv_buf = NULL;
  size_t priv_buf_len = 0;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(type);

  if (!priv_ec)
    goto fail;

  if (!EC_KEY_generate_key(priv_ec))
    goto fail;

  priv_buf_len = EC_KEY_priv2buf(priv_ec, &priv_buf);

  if ((int)priv_buf_len <= 0)
    goto fail;

  EC_KEY_free(priv_ec);

  *priv = priv_buf;
  *priv_len = priv_buf_len;

  return true;

fail:
  if (priv_ec)
    EC_KEY_free(priv_ec);

  if (priv_buf)
    free(priv_buf);

  return false;
}

bool
bcrypto_ecdsa_create_pub(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **pub,
  size_t *pub_len
) {
  BN_CTX *ctx = NULL;
  EC_KEY *priv_ec = NULL;
  EC_POINT *pub_point = NULL;
  uint8_t *pub_buf = NULL;
  size_t pub_buf_len = 0;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(type);

  if (!priv_ec)
    goto fail;

  if (!EC_KEY_oct2priv(priv_ec, priv, priv_len))
    goto fail;

  const EC_GROUP *group = EC_KEY_get0_group(priv_ec);
  assert(group);

  pub_point = EC_POINT_new(group);

  if (!pub_point)
    goto fail;

  const BIGNUM *priv_bn = EC_KEY_get0_private_key(priv_ec);
  assert(priv_bn);

  if (!EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, ctx))
    goto fail;

  if (!EC_KEY_set_public_key(priv_ec, pub_point))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  pub_buf_len = EC_KEY_key2buf(priv_ec, form, &pub_buf, ctx);

  if ((int)pub_buf_len <= 0)
    goto fail;

  EC_KEY_free(priv_ec);
  EC_POINT_free(pub_point);
  BN_CTX_free(ctx);

  *pub = pub_buf;
  *pub_len = pub_buf_len;

  return true;

fail:
  if (priv_ec)
    EC_KEY_free(priv_ec);

  if (pub_point)
    EC_POINT_free(pub_point);

  if (ctx)
    BN_CTX_free(ctx);

  if (pub_buf)
    free(pub_buf);

  return false;
}

bool
bcrypto_ecdsa_convert_pub(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
) {
  BN_CTX *ctx = NULL;
  EC_KEY *pub_ec = NULL;
  uint8_t *npub_buf = NULL;
  size_t npub_buf_len = 0;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, ctx))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  npub_buf_len = EC_KEY_key2buf(pub_ec, form, &npub_buf, ctx);

  if ((int)npub_buf_len <= 0)
    goto fail;

  EC_KEY_free(pub_ec);
  BN_CTX_free(ctx);

  *npub = npub_buf;
  *npub_len = npub_buf_len;

  return true;

fail:
  if (pub_ec)
    EC_KEY_free(pub_ec);

  if (ctx)
    BN_CTX_free(ctx);

  if (npub_buf)
    free(npub_buf);

  return false;
}

bool
bcrypto_ecdsa_sign(
  const char *name,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *priv,
  size_t priv_len,
  uint8_t **r,
  size_t *r_len,
  uint8_t **s,
  size_t *s_len
) {
  EC_KEY *priv_ec = NULL;
  ECDSA_SIG *sig_ec = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(type);

  if (!priv_ec)
    goto fail;

  if (!EC_KEY_oct2priv(priv_ec, priv, priv_len))
    goto fail;

  sig_ec = ECDSA_do_sign(msg, msg_len, priv_ec);

  if (!sig_ec)
    goto fail;

  const EC_GROUP *group = EC_KEY_get0_group(priv_ec);
  int bits = EC_GROUP_get_degree(group);
  size_t size = (bits + 7) / 8;

  if (!bcrypto_ecdsa_sig2rs(group, sig_ec, r, s))
    goto fail;

  *r_len = size;
  *s_len = size;

  EC_KEY_free(priv_ec);
  ECDSA_SIG_free(sig_ec);

  return true;

fail:
  if (priv_ec)
    EC_KEY_free(priv_ec);

  if (sig_ec)
    ECDSA_SIG_free(sig_ec);

  return false;
}

// Note: could do this in js-land by
// hard-coding all the orders.
bool
bcrypto_ecdsa_verify_priv(
  const char *name,
  const uint8_t *priv,
  size_t priv_len
) {
  EC_KEY *priv_ec = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(type);

  if (!priv_ec)
    goto fail;

  if (!EC_KEY_oct2priv(priv_ec, priv, priv_len))
    goto fail;

  if (!EC_KEY_check_key(priv_ec))
    goto fail;

  EC_KEY_free(priv_ec);

  return true;

fail:
  if (priv_ec)
    EC_KEY_free(priv_ec);

  return false;
}

bool
bcrypto_ecdsa_verify(
  const char *name,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *r,
  size_t r_len,
  const uint8_t *s,
  size_t s_len,
  const uint8_t *pub,
  size_t pub_len
) {
  BN_CTX *ctx = NULL;
  EC_KEY *pub_ec = NULL;
  ECDSA_SIG *sig_ec = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, ctx))
    goto fail;

  sig_ec = bcrypto_ecdsa_rs2sig(r, r_len, s, s_len);

  if (!sig_ec)
    goto fail;

  if (!ECDSA_do_verify(msg, msg_len, sig_ec, pub_ec))
    goto fail;

  EC_KEY_free(pub_ec);
  ECDSA_SIG_free(sig_ec);
  BN_CTX_free(ctx);

  return true;

fail:
  if (pub_ec)
    EC_KEY_free(pub_ec);

  if (sig_ec)
    ECDSA_SIG_free(sig_ec);

  if (ctx)
    BN_CTX_free(ctx);

  return false;
}

bool
bcrypto_ecdsa_verify_pub(const char *name, const uint8_t *pub, size_t pub_len) {
  BN_CTX *ctx = NULL;
  EC_KEY *pub_ec = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, ctx))
    goto fail;

  if (!EC_KEY_check_key(pub_ec))
    goto fail;

  EC_KEY_free(pub_ec);
  BN_CTX_free(ctx);

  return true;

fail:
  if (pub_ec)
    EC_KEY_free(pub_ec);

  if (ctx)
    BN_CTX_free(ctx);

  return false;
}

bool
bcrypto_ecdsa_ecdh(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **secret,
  size_t *secret_len
) {
  BN_CTX *ctx = NULL;
  EC_KEY *priv_ec = NULL;
  EC_KEY *pub_ec = NULL;
  uint8_t *raw_secret = NULL;
  BIGNUM *secret_bn = NULL;
  EC_POINT *secret_point = NULL;
  uint8_t *secret_buf = NULL;
  size_t secret_buf_len = 0;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(type);

  if (!priv_ec)
    goto fail;

  if (!EC_KEY_oct2priv(priv_ec, priv, priv_len))
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, ctx))
    goto fail;

  const EC_POINT *pub_point = EC_KEY_get0_public_key(pub_ec);
  assert(pub_point);

  const EC_GROUP *group = EC_KEY_get0_group(priv_ec);
  assert(group);

  int field_size = EC_GROUP_get_degree(group);
  size_t raw_secret_len = (field_size + 7) / 8;

  raw_secret = malloc(raw_secret_len);

  if (!raw_secret)
    goto fail;

  raw_secret_len = ECDH_compute_key(
    raw_secret,
    raw_secret_len,
    pub_point,
    priv_ec,
    NULL
  );

  if ((int)raw_secret_len <= 0)
    goto fail;

  secret_bn = BN_bin2bn(raw_secret, raw_secret_len, NULL);

  if (!secret_bn)
    goto fail;

  secret_point = EC_POINT_new(group);

  if (!secret_point)
    goto fail;

  if (!EC_POINT_mul(group, secret_point, secret_bn, NULL, NULL, ctx))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  secret_buf_len = EC_POINT_point2buf(
    group,
    secret_point,
    form,
    &secret_buf,
    NULL
  );

  if ((int)secret_buf_len <= 0)
    goto fail;

  EC_KEY_free(priv_ec);
  EC_KEY_free(pub_ec);
  free(raw_secret);
  BN_clear_free(secret_bn);
  EC_POINT_free(secret_point);
  BN_CTX_free(ctx);

  *secret = secret_buf;
  *secret_len = secret_buf_len;

  return true;

fail:
  if (priv_ec)
    EC_KEY_free(priv_ec);

  if (pub_ec)
    EC_KEY_free(pub_ec);

  if (raw_secret)
    free(raw_secret);

  if (secret_bn)
    BN_clear_free(secret_bn);

  if (secret_point)
    EC_POINT_free(secret_point);

  if (ctx)
    BN_CTX_free(ctx);

  if (secret_buf)
    free(secret_buf);

  return false;
}

bool
bcrypto_ecdsa_tweak_priv(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  const uint8_t *tweak,
  size_t tweak_len,
  uint8_t **npriv,
  size_t *npriv_len
) {
  BN_CTX *ctx = NULL;
  BIGNUM *order_bn = NULL;
  BIGNUM *priv_bn = NULL;
  BIGNUM *tweak_bn = NULL;
  uint8_t *npriv_buf = NULL;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  size_t size;
  order_bn = bcrypto_ecdsa_order(name, &size);

  if (!order_bn)
    goto fail;

  if (priv_len != size || tweak_len != size)
    goto fail;

  priv_bn = BN_bin2bn(priv, priv_len, NULL);

  if (!priv_bn)
    goto fail;

  if (BN_is_zero(priv_bn))
    goto fail;

  if (BN_cmp(priv_bn, order_bn) >= 0)
    goto fail;

  tweak_bn = BN_bin2bn(tweak, tweak_len, NULL);

  if (!tweak_bn)
    goto fail;

  if (!BN_mod_add(priv_bn, priv_bn, tweak_bn, order_bn, ctx))
    goto fail;

  if (BN_is_zero(priv_bn))
    goto fail;

  assert((size_t)BN_num_bytes(priv_bn) <= size);

  npriv_buf = malloc(size);

  if (!npriv_buf)
    goto fail;

  assert(BN_bn2binpad(priv_bn, npriv_buf, size) > 0);

  BN_free(order_bn);
  BN_clear_free(priv_bn);
  BN_clear_free(tweak_bn);
  BN_CTX_free(ctx);

  *npriv = npriv_buf;
  *npriv_len = size;

  return true;

fail:
  if (order_bn)
    BN_free(order_bn);

  if (priv_bn)
    BN_clear_free(priv_bn);

  if (tweak_bn)
    BN_clear_free(tweak_bn);

  if (ctx)
    BN_CTX_free(ctx);

  if (npriv_buf)
    free(npriv_buf);

  return false;
}

bool
bcrypto_ecdsa_tweak_pub(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  const uint8_t *tweak,
  size_t tweak_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
) {
  BN_CTX *ctx = NULL;
  EC_KEY *pub_ec = NULL;
  BIGNUM *tweak_bn = NULL;
  EC_POINT *tweak_point = NULL;
  uint8_t *npub_buf = NULL;
  size_t npub_buf_len = 0;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, ctx))
    goto fail;

  tweak_bn = BN_bin2bn(tweak, tweak_len, NULL);

  if (!tweak_bn)
    goto fail;

  const EC_POINT *key_point = EC_KEY_get0_public_key(pub_ec);
  assert(key_point);

  const EC_GROUP *group = EC_KEY_get0_group(pub_ec);
  assert(group);

  tweak_point = EC_POINT_new(group);

  if (!tweak_point)
    goto fail;

  if (!EC_POINT_mul(group, tweak_point, tweak_bn, NULL, NULL, ctx))
    goto fail;

  if (!EC_POINT_add(group, tweak_point, key_point, tweak_point, ctx))
    goto fail;

  // EC_POINT_mod??

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  npub_buf_len = EC_POINT_point2buf(group, tweak_point, form, &npub_buf, ctx);

  if ((int)npub_buf_len <= 0)
    goto fail;

  EC_KEY_free(pub_ec);
  BN_clear_free(tweak_bn);
  EC_POINT_free(tweak_point);
  BN_CTX_free(ctx);

  *npub = npub_buf;
  *npub_len = npub_buf_len;

  return true;

fail:
  if (pub_ec)
    EC_KEY_free(pub_ec);

  if (tweak_bn)
    BN_clear_free(tweak_bn);

  if (tweak_point)
    EC_POINT_free(tweak_point);

  if (ctx)
    BN_CTX_free(ctx);

  if (npub_buf)
    free(npub_buf);

  return false;
}

#else

bool
bcrypto_ecdsa_generate(const char *name, uint8_t **priv, size_t *priv_len) {
  return false;
}

bool
bcrypto_ecdsa_create_pub(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **pub,
  size_t *pub_len
) {
  return false;
}

bool
bcrypto_ecdsa_convert_pub(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
) {
  return false;
}

bool
bcrypto_ecdsa_sign(
  const char *name,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *priv,
  size_t priv_len,
  uint8_t **r,
  size_t *r_len,
  uint8_t **s,
  size_t *s_len
) {
  return false;
}

bool
bcrypto_ecdsa_verify_priv(
  const char *name,
  const uint8_t *priv,
  size_t priv_len
) {
  return false;
}

bool
bcrypto_ecdsa_verify(
  const char *name,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *r,
  size_t r_len,
  const uint8_t *s,
  size_t s_len,
  const uint8_t *pub,
  size_t pub_len
) {
  return false;
}

bool
bcrypto_ecdsa_verify_pub(const char *name, const uint8_t *pub, size_t pub_len) {
  return false;
}

bool
bcrypto_ecdsa_ecdh(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **secret,
  size_t *secret_len
) {
  return false;
}

bool
bcrypto_ecdsa_tweak_priv(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  const uint8_t *tweak,
  size_t tweak_len,
  uint8_t **npriv,
  size_t *npriv_len
) {
  return false;
}

bool
bcrypto_ecdsa_tweak_pub(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  const uint8_t *tweak,
  size_t tweak_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
) {
  return false;
}

#endif
