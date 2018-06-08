#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "openssl/ecdsa.h"
#include "ecdsa.h"

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

  if (strcmp(alg, "p192") == 0)
    type = NID_prime192v1;
  else if (strcmp(alg, "p224") == 0)
    type = NID_secp224r1;
  else if (strcmp(alg, "p256") == 0)
    type = NID_prime256v1;
  else if (strcmp(alg, "p384") == 0)
    type = NID_secp384r1;
  else if (strcmp(alg, "p521") == 0)
    type = NID_secp521r1;
  else if (strcmp(alg, "secp256k1") == 0)
    type = NID_secp256k1;

  return type;
}

static BIGNUM *
bcrypto_ecdsa_order(const char *name, size_t *size) {
  EC_KEY *key_ec = NULL;
  BIGNUM *order_bn = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  // We need the group, and I have no
  // idea how to easily get it by nid
  // other than allocating a key!
  key_ec = EC_KEY_new_by_curve_name(type);

  if (!key_ec)
    goto fail;

  const EC_GROUP *group = EC_KEY_get0_group(key_ec)
  assert(group);

  order_bn = BN_new();

  if (!order_bn)
    goto fail;

  if (!EC_group_get_order(group, order_bn, NULL))
    goto fail;

  if (size) {
    int field_size = EC_GROUP_get_degree(group);
    *size = (field_size + 7) / 8;
  }

  EC_KEY_free(key_ec);

  return order_bn;

fail:
  if (key_ec)
    EC_KEY_free(key_ec);

  if (order_bn)
    BN_free(order_bn);

  return NULL;
}

// Note: could do this in js-land by
// hard-coding all the orders.
bool
bcrypto_ecdsa_generate(const char *name, uint8_t **priv, size_t *priv_len) {
  EC_KEY *priv_ec = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(type);

  if (!priv_ec)
    goto fail;

  if (!EC_KEY_generate_key(priv_ec))
    goto fail;

  uint8_t *buf = NULL;
  size_t buf_len = EC_KEY_priv2buf(priv_ec, &buf);

  if ((int)buf_len <= 0)
    goto fail;

  EC_KEY_free(priv_ec);

  *priv = buf;
  *priv_len = buf_len;

  return true;

fail:
  if (priv_ec)
    EC_KEY_free(priv_ec);

  return false;
}

bool
bcrypto_ecdsa_create_pub(
  const char *name,
  uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **pub,
  size_t *pub_len
) {
  EC_KEY *priv_ec = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(type);

  if (!priv_ec)
    goto fail;

  if (!EC_KEY_oct2priv(priv_ec, priv, priv_len, NULL))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  uint8_t *buf = NULL;
  size_t buf_len = EC_KEY_key2buf(priv_ec, form, &buf, NULL);

  if ((int)buf_len <= 0)
    goto fail;

  EC_KEY_free(priv_ec);

  *pub = buf;
  *pub_len = buf_len;

  return true;

fail:
  if (priv_ec)
    EC_KEY_free(priv_ec);

  if (buf)
    free(buf);

  return false;
}

bool
bcrypto_ecdsa_convert_pub(
  const char *name,
  uint8_t *pub,
  size_t pub_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
) {
  EC_KEY *pub_ec = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, NULL))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  uint8_t *buf = NULL;
  size_t buf_len = EC_KEY_key2buf(pub_ec, form, &buf, NULL);

  if ((int)buf_len <= 0)
    goto fail;

  EC_KEY_free(pub_ec);

  *npub = buf;
  *npub_len = buf_len;

  return true;

fail:
  if (pub_ec)
    EC_KEY_free(pub_ec);

  return false;
}

bool
bcrypto_ecdsa_sign(
  const char *name,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *priv,
  size_t priv_len,
  uint8_t **sig,
  size_t *sig_len
) {
  EC_KEY *priv_ec = NULL;
  uint8_t *buf = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(type);

  if (!priv_ec)
    goto fail;

  if (!EC_KEY_oct2priv(priv_ec, priv, priv_len, NULL))
    goto fail;

  size_t buf_len = ECDSA_size(priv_ec);

  buf = malloc(buf_len);

  if (!buf)
    goto fail;

  if (!ECDSA_sign(type, msg, msg_len, buf, &buf_len, priv_ec))
    goto fail;

  *sig = buf;
  *sig_len = buf_len;

  EC_KEY_free(priv_ec);

  return true;

fail:
  if (priv_ec)
    EC_KEY_free(priv_ec);

  if (buf)
    free(buf);

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

  if (!EC_KEY_oct2priv(priv_ec, priv, priv_len, NULL))
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
  const uint8_t *sig,
  size_t sig_len,
  const uint8_t *pub,
  size_t pub_len
) {
  EC_KEY *pub_ec = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, NULL))
    goto fail;

  if (!ECDSA_verify(type, msg, msg_len, sig, sig_len, pub_ec))
    goto fail;

  EC_KEY_free(pub_ec);

  return true;

fail:
  if (pub_ec)
    EC_KEY_free(pub_ec);

  return false;
}

bool
bcrypto_ecdsa_verify_pub(const char *name, const uint8_t *pub, size_t pub_len) {
  EC_KEY *pub_ec = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, NULL))
    goto fail;

  if (!ECDSA_check_key(pub_ec))
    goto fail;

  EC_KEY_free(pub_ec);

  return true;

fail:
  if (pub_ec)
    EC_KEY_free(pub_ec);

  return false;
}

bool
bcrypto_ecdsa_ecdh(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  const uint8_t *pub,
  size_t pub_len,
  bool compress,
  uint8_t **secret,
  size_t *secret_len
) {
  EC_KEY *priv_ec = NULL;
  EC_KEY *pub_ec = NULL;
  uint8_t *dsecret = NULL;
  BIGNUM *secret_bn = NULL;
  EC_POINT *secret_point = NULL;
  uint8_t *buf = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(type);

  if (!priv_ec)
    goto fail;

  if (!EC_KEY_oct2priv(priv_ec, priv, priv_len, NULL))
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, NULL))
    goto fail;

  const EC_POINT *pub_point = EC_KEY_get0_public_key(pub_ec);
  assert(pub_point);

  const EC_GROUP *group = EC_KEY_get0_group(priv_ec);
  assert(group);

  int field_size = EC_GROUP_get_degree(group);
  size_t dsecret_len = (field_size + 7) / 8;

  dsecret = malloc(dsecret_len);

  if (!dsecret)
    goto fail;

  dsecret_len = ECDH_compute_key(
    dsecret,
    dsecret_len,
    pub_point,
    priv_ec,
    NULL
  );

  if ((int)dsecret_len <= 0)
    goto fail;

  secret_bn = BN_bin2bn(dsecret, dsecret_len, NULL);

  if (!secret_bn)
    goto fail;

  secret_point = EC_POINT_bn2point(group, secret_bn, NULL, NULL);

  if (!secret_point)
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  size_t buf_len = EC_POINT_point2buf(group, secret_point, form, &buf, NULL);

  if ((int)buf_len <= 0)
    goto fail;

  EC_KEY_free(priv_ec);
  EC_KEY_free(pub_ec);
  free(dsecret);
  BN_clear_free(secret_bn);
  EC_POINT_free(secret_point);

  *secret = buf;
  *secret_len = buf_len;

  return true;

fail:
  if (priv_ec)
    EC_KEY_free(priv_ec);

  if (pub_ec)
    EC_KEY_free(pub_ec);

  if (dsecret)
    free(dsecret);

  if (secret_bn)
    BN_clear_free(secret_bn);

  if (secret_point)
    EC_POINT_free(secret_point);

  if (buf)
    free(buf);

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
  BIGNUM *order_bn = NULL;
  BIGNUM *key_bn = NULL;
  BIGNUM *tweak_bn = NULL;
  uint8_t *buf = NULL;

  size_t size;
  order_bn = bcrypto_ecdsa_order(name, &size);

  if (!order_bn)
    goto fail;

  if (priv_len != size || tweak_len != size)
    goto fail;

  key_bn = BN_bin2bn(priv, priv_len, NULL);

  if (!key_bn)
    goto fail;

  if (BN_is_zero(key_bn))
    goto fail;

  if (BN_cmp(key_bn, order_bn) >= 0)
    goto fail;

  tweak_bn = BN_bin2bn(tweak, tweak_len, NULL);

  if (!tweak_bn)
    goto fail;

  // BN_mod_add??
  if (!BN_add(key_bn, key_bn, tweak_bn))
    goto fail;

  if (!BN_mod(key_bn, key_bn, order_bn))
    goto fail;

  if (BN_is_zero(key_bn))
    goto fail;

  assert(BN_num_bytes(key_bn) <= size);

  buf = malloc(size);

  if (!buf)
    goto fail;

  assert(BN_bn2binpad(key_bn, buf, size) > 0);

  BN_free(order_bn);
  BN_clear_free(key_bn);
  BN_clear_free(tweak_bn);

  *npriv = buf;
  *npriv_len = size;

  return true;

fail:
  if (order_bn)
    BN_free(order_bn);

  if (key_bn)
    BN_clear_free(key_bn);

  if (tweak_bn)
    BN_clear_free(tweak_bn);

  if (buf)
    free(buf);

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
  EC_KEY *key_ec = NULL;
  BIGNUM *tweak_bn = NULL;
  EC_POINT *tweak_point = NULL;
  uint8_t *buf = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  key_ec = EC_KEY_new_by_curve_name(type);

  if (!key_ec)
    goto fail;

  if (!EC_KEY_oct2key(key_ec, pub, pub_len, NULL))
    goto fail;

  tweak_bn = BN_bin2bn(tweak, tweak_len, NULL);

  if (!tweak_bn)
    goto fail;

  const EC_POINT *key_point = EC_KEY_get0_public_key(key_ec);
  assert(key_point);

  const EC_GROUP *group = EC_KEY_get0_group(key_ec);
  assert(group);

  tweak_point = EC_POINT_bn2point(group, tweak_bn, NULL, NULL);

  if (!tweak_point)
    goto fail;

  if (!EC_POINT_add(group, tweak_point, key_point, tweak_point, NULL))
    goto fail;

  // EC_POINT_mod??

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  size_t buf_len = EC_POINT_point2buf(group, tweak_point, form, &buf, NULL);

  if ((int)buf_len <= 0)
    goto fail;

  EC_KEY_free(key_ec);
  BN_clear_free(tweak_bn);
  EC_POINT_free(tweak_point);

  *npub = buf;
  *npub_len = buf_len;

  return true;

fail:
  if (key_ec)
    EC_KEY_free(key_ec);

  if (tweak_bn)
    BN_clear_free(tweak_bn);

  if (tweak_point)
    EC_POINT_free(tweak_point);

  if (buf)
    free(buf);

  return false;
}

bool
bcrypto_ecdsa_is_low_der(const char *name, const uint8_t *sig, size_t sig_len) {
  ECDSA_SIG *sig_ec = NULL;
  BIGNUM *order_bn = NULL;

  if (!d2i_ECDSA_SIG(&sig_ec, &sig, sig_len))
    goto fail;

  const BIGNUM *r = ECDSA_SIG_get0_r(sig_ec);
  assert(r);

  const BIGNUM *s = ECDSA_SIG_get0_s(sig_ec);
  assert(s);

  if (BN_is_zero(r))
    goto fail;

  if (BN_is_negative(r))
    goto fail;

  if (BN_is_zero(s))
    goto fail;

  if (BN_is_negative(s))
    goto fail;

  size_t size;
  order_bn = bcrypto_ecdsa_order(name, &size);

  if (!order_bn)
    goto fail;

  if (BN_num_bytes(r) > size)
    goto fail;

  if (BN_num_bytes(s) > size)
    goto fail;

  if (!BN_rshift1(order_bn, order_bn))
    goto fail;

  if (BN_cmp(s, order_bn) > 0)
    goto fail;

  ECDSA_SIG_free(sig_ec);
  BN_free(order_bn);

  return true;

fail:
  if (sig_ec)
    ECDSA_SIG_free(sig_ec);

  if (order_bn)
    BN_free(order_bn);

  return false;
}
