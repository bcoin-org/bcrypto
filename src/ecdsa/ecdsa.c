#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "openssl/ecdsa.h"

// https://github.com/openssl/openssl/blob/master/include/openssl/ec.h

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

// Note: could do this in js-land by
// hard-coding all the orders.
bool
bcrypto_ecdsa_generate(const char *name, uint8_t **key, size_t *key_len) {
  EC_KEY *priv = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  priv = EC_KEY_new_by_curve_name(type);

  if (!priv)
    goto fail;

  if (!EC_KEY_generate_key(priv))
    goto fail;

  uint8_t *buf = NULL;
  size_t s = EC_KEY_priv2buf(priv, &buf);

  if (!buf)
    goto fail;

  EC_KEY_free(priv);

  *key = buf;
  *key_len = s;

  return true;

fail:
  if (priv)
    EC_KEY_free(priv);

  return false;
}

bool
bcrypto_ecdsa_create_pub(
  const char *name,
  uint8_t *key,
  size_t key_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
) {
  EC_KEY *priv = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  priv = EC_KEY_new_by_curve_name(type);

  if (!priv)
    goto fail;

  if (!EC_KEY_oct2priv(priv, key, key_len, NULL))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  uint8_t *buf = NULL;
  size_t s = EC_KEY_key2buf(priv, form, &buf, NULL);

  if (!buf)
    goto fail;

  EC_KEY_free(priv);

  *out = buf;
  *out_len = s;

  return true;

fail:
  if (priv)
    EC_KEY_free(priv);

  return false;
}

bool
bcrypto_ecdsa_convert_pub(
  const char *name,
  uint8_t *key,
  size_t key_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
) {
  EC_KEY *pub = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  pub = EC_KEY_new_by_curve_name(type);

  if (!pub)
    goto fail;

  if (!EC_KEY_oct2key(pub, key, key_len, NULL))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  uint8_t *buf = NULL;
  size_t s = EC_KEY_key2buf(pub, form, &buf, NULL);

  if (!buf)
    goto fail;

  EC_KEY_free(pub);

  *out = buf;
  *out_len = s;

  return true;

fail:
  if (pub)
    EC_KEY_free(pub);

  return false;
}

bool
bcrypto_ecdsa_sign(
  const char *name,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *key,
  size_t key_len,
  const uint8_t **sig,
  size_t *sig_len
) {
  EC_KEY *priv = NULL;
  uint8_t *s = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  priv = EC_KEY_new_by_curve_name(type);

  if (!priv)
    goto fail;

  if (!EC_KEY_oct2priv(priv, key, key_len, NULL))
    goto fail;

  size_t s_len = ECDSA_size(priv);

  s = malloc(s_len);

  if (!s)
    goto fail;

  if (!ECDSA_sign(type, msg, msg_len, s, &s_len, priv))
    goto fail;

  *sig = s;
  *sig_len = s_len;

  EC_KEY_free(priv);

  return true;

fail:
  if (priv)
    EC_KEY_free(priv);

  if (s)
    free(s);

  return false;
}

// Note: could do this in js-land by
// hard-coding all the orders.
bool
bcrypto_ecdsa_verify_priv(
  const char *name,
  const uint8_t *key,
  size_t key_len
) {
  EC_KEY *priv = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  priv = EC_KEY_new_by_curve_name(type);

  if (!priv)
    goto fail;

  if (!EC_KEY_oct2priv(priv, key, key_len, NULL))
    goto fail;

  if (!EC_KEY_check_key(priv))
    goto fail;

  EC_KEY_free(priv);

  return true;

fail:
  if (priv)
    EC_KEY_free(priv);

  return false;
}

bool
bcrypto_ecdsa_verify(
  const char *name,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *sig,
  size_t sig_len,
  const uint8_t *key,
  size_t key_len
) {
  EC_KEY *pub = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  pub = EC_KEY_new_by_curve_name(type);

  if (!pub)
    goto fail;

  if (!EC_KEY_oct2key(pub, key, key_len, NULL))
    goto fail;

  if (!ECDSA_verify(type, msg, msg_len, sig, sig_len, pub))
    goto fail;

  EC_KEY_free(pub);

  return true;

fail:
  if (pub)
    EC_KEY_free(pub);

  return false;
}

bool
bcrypto_ecdsa_verify_pub(
  const char *name,
  const uint8_t *key,
  size_t key_len
) {
  EC_KEY *pub = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  pub = EC_KEY_new_by_curve_name(type);

  if (!pub)
    goto fail;

  if (!EC_KEY_oct2key(pub, key, key_len, NULL))
    goto fail;

  if (!ECDSA_check_key(pub))
    goto fail;

  EC_KEY_free(pub);

  return true;

fail:
  if (pub)
    EC_KEY_free(pub);

  return false;
}

bool
bcrypto_ecdsa_ecdh(
  const char *name,
  const uint8_t *privkey,
  size_t privkey_len,
  const uint8_t *pubkey,
  size_t pubkey_len,
  bool compress,
  const uint8_t **out,
  size_t *out_len
) {
  EC_KEY *priv = NULL;
  EC_KEY *pub = NULL;
  uint8_t *secret = NULL;
  BIGNUM *n = NULL;
  uint8_t *buf = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  priv = EC_KEY_new_by_curve_name(type);

  if (!priv)
    goto fail;

  if (!EC_KEY_oct2priv(priv, privkey, privkey_len, NULL))
    goto fail;

  pub = EC_KEY_new_by_curve_name(type);

  if (!pub)
    goto fail;

  if (!EC_KEY_oct2key(pub, pubkey, pubkey_len, NULL))
    goto fail;

  const EC_POINT *point = EC_KEY_get0_public_key(pub);
  assert(point);

  // https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman
  int field_size = EC_GROUP_get_degree(EC_KEY_get0_group(priv));
  size_t secret_len = (field_size + 7) / 8;

  secret = malloc(secret_len);

  if (!secret)
    goto fail;

  secret_len = ECDH_compute_key(secret, secret_len, point, priv, NULL);

  if ((int)secret_len <= 0)
    goto fail;

  n = BN_bin2bn(secret, secret_len, NULL);

  if (!n)
    goto fail;

  const EC_GROUP *group = EC_KEY_get0_group(priv);
  assert(group);

  EC_POINT *point = EC_POINT_bn2point(group, n, NULL, NULL);

  if (!point)
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  size_t buf_len = EC_POINT_point2buf(group, point, form, &buf, NULL);

  if ((int)buf_len <= 0)
    goto fail;

  EC_KEY_free(priv);
  EC_KEY_free(pub);
  free(secret);
  BN_free_clear(n);
  EC_POINT_free(point);

  *out = buf;
  *out_len = buf_len;

  return true;

fail:
  if (priv)
    EC_KEY_free(priv);

  if (pub)
    EC_KEY_free(pub);

  if (secret)
    free(secret);

  if (n)
    BN_free_clear(n);

  if (point)
    EC_POINT_free(point);

  if (buf)
    free(buf);

  return false;
}

/*
 * TODO
 */

bool
bcrypto_ecdsa_tweak_priv(
  const char *name,
  const uint8_t *key,
  size_t key_len,
  const uint8_t *tweak,
  size_t tweak_len,
  const uint8_t **out,
  size_t *out_len
) {
  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  // LOGIC:
  // k = bin2bn(tweak)
  // k = k + bin2bn(key)
  // k = k % N
  // return BN_bn2bin(k) - padded to field_size

fail:
  return false;
}

bool
bcrypto_ecdsa_tweak_pub(
  const char *name,
  const uint8_t *key,
  size_t key_len,
  const uint8_t *tweak,
  size_t tweak_len,
  bool compress,
  const uint8_t **out,
  size_t *out_len
) {
  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  // LOGIC:
  // key_point = oct2point(key)
  // tweak_bn = bin2bn(tweak)
  // tweak_point = bn2point(tweak_bn)
  // point = tweak_point + key_point
  // return point2buf(point)
fail:
  return false;
}

bool
bcrypto_ecdsa_is_low_der(
  const char *name,
  const uint8_t *sig,
  size_t sig_len
) {
  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  // Note: could do this in js-land by
  // hard-coding all the half-orders.
  // LOGIC:
  // key = EC_KEY_new_by_curve_name(type);
  // group = EC_KEY_get0_group(key)
  // N = BN_new()
  // EC_group_get_order(group, order, null)
  // signature = d2i_ECDSA_SIG(sig)
  // s = ECDSA_SIG_get0_s(signature)
  // return s != 0 && s <= (N >> 1)
fail:
  return false;
}

bool
bcrypto_ecdsa_is_low_s(
  const char *name,
  const uint8_t *sval,
  size_t sval_len
) {
  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  // Note: could do this in js-land by
  // hard-coding all the half-orders.
  // LOGIC:
  // key = EC_KEY_new_by_curve_name(type);
  // group = EC_KEY_get0_group(key)
  // N = BN_new()
  // EC_group_get_order(group, order, null)
  // s = BN_bin2bn(s)
  // return s != 0 && s <= (N >> 1)
fail:
  return false;
}

// Maybe also:
// recover - no openssl function - hard
// signatureImport
// signatureImportLax
// signatureExport
// fromDER
// toDER

/*
 * Helpers
 */

static EC_KEY *
bcrypto_ecdsa_buf2priv(int type, const uint8_t *buf, size_t buf_len) {
  BIGNUM *n = NULL;
  EC_KEY *priv = NULL;

  n = BN_bin2bn(buf, buf_len, NULL);

  if (!n)
    goto fail;

  priv = EC_KEY_new_by_curve_name(type);

  if (!priv)
    goto fail;

  if (!EC_KEY_set_private_key(priv, n))
    goto fail;

  BN_free_clear(n);

  return priv;

fail:
  if (n)
    BN_free_clear(n);

  if (priv)
    EC_KEY_free(priv);

  return NULL;
}

static bool
bcrypto_ecdsa_priv2buf(const EC_KEY *key, uint8_t **buf, size_t *buf_len) {
  const BIGNUM *n = EC_KEY_get0_private_key(key);
  assert(n);

  int field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
  size_t size = (field_size + 7) / 8;

  size_t s = BN_num_bytes(n);
  assert(s <= size);
  size_t off = size - s;

  uint8_t *nd = malloc(size);

  if (!nd)
    return false;

  memset(nd, 0x00, off);
  assert(BN_bn2bin(n, &nd[off]) != 0);

  *buf = nd;
  *buf_len = size;

  return true;
}
