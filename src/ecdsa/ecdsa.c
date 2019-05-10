#include "../compat.h"

#ifdef BCRYPTO_HAS_ECDSA

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "ecdsa.h"

#include "openssl/ecdsa.h"
#include "openssl/objects.h"
#include "openssl/x509.h"
#include "../random/random.h"

/*
 * Helpers
 */

static int
bcrypto_ecdsa_curve(const char *name) {
  int type = -1;

  if (name == NULL)
    return type;

  if (strcmp(name, "P192") == 0)
    type = NID_X9_62_prime192v1;
  else if (strcmp(name, "P224") == 0)
    type = NID_secp224r1;
  else if (strcmp(name, "P256") == 0)
    type = NID_X9_62_prime256v1;
  else if (strcmp(name, "P384") == 0)
    type = NID_secp384r1;
  else if (strcmp(name, "P521") == 0)
    type = NID_secp521r1;
  else if (strcmp(name, "SECP256K1") == 0)
    type = NID_secp256k1;

  return type;
}

static int
bcrypto_ecdsa_valid_scalar(bcrypto_ecdsa_t *ec, const uint8_t *scalar) {
  if (scalar == NULL)
    return 0;

  return memcmp(scalar, ec->zero, ec->scalar_size) != 0
      && memcmp(scalar, ec->order, ec->scalar_size) < 0;
}

static int
bcrypto_ecdsa_valid_point(bcrypto_ecdsa_t *ec,
                          const uint8_t *raw,
                          size_t raw_len) {
  if (raw == NULL)
    return 0;

  if (raw_len < 1 + ec->size)
    return 0;

  switch (raw[0]) {
    case 0x02:
    case 0x03:
      return raw_len == 1 + ec->size;
    case 0x04:
      return raw_len == 1 + ec->size * 2;
    case 0x06:
    case 0x07:
      return raw_len == 1 + ec->size * 2
          && (raw[0] & 1) == (raw[raw_len - 1] & 1);
    default:
      return 0;
  }
}

/*
 * Public Key
 */

static int
bcrypto_ecdsa_pubkey_from_ec_key(bcrypto_ecdsa_t *ec,
                                 bcrypto_ecdsa_pubkey_t *pub,
                                 const EC_KEY *key);

void
bcrypto_ecdsa_pubkey_encode(bcrypto_ecdsa_t *ec,
                            uint8_t *out,
                            size_t *out_len,
                            const bcrypto_ecdsa_pubkey_t *pub,
                            int compress) {
  if (compress) {
    out[0] = 0x02 | (pub->y[ec->size - 1] & 1);
    memcpy(&out[1], &pub->x[0], ec->size);
    *out_len = 1 + ec->size;
  } else {
    out[0] = 0x04;
    memcpy(&out[1], &pub->x[0], ec->size);
    memcpy(&out[1 + ec->size], &pub->y[0], ec->size);
    *out_len = 1 + ec->size * 2;
  }
}

int
bcrypto_ecdsa_pubkey_decode(bcrypto_ecdsa_t *ec,
                            bcrypto_ecdsa_pubkey_t *pub,
                            const uint8_t *raw,
                            size_t raw_len) {
  if (!bcrypto_ecdsa_valid_point(ec, raw, raw_len))
    return 0;

  if (!EC_KEY_oct2key(ec->key, raw, raw_len, ec->ctx))
    return 0;

  if (raw[0] >= 0x04) {
    const EC_POINT *point = EC_KEY_get0_public_key(ec->key);
    assert(point != NULL);

    if (EC_POINT_is_on_curve(ec->group, point, ec->ctx) <= 0)
      return 0;
  }

  if (!bcrypto_ecdsa_pubkey_from_ec_key(ec, pub, ec->key))
    return 0;

  return 1;
}

static EC_KEY *
bcrypto_ecdsa_pubkey_to_ec_key(bcrypto_ecdsa_t *ec,
                               const bcrypto_ecdsa_pubkey_t *pub) {
  EC_KEY *key = NULL;
  uint8_t raw[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t raw_len;

  key = EC_KEY_new_by_curve_name(ec->type);

  if (key == NULL)
    goto fail;

  bcrypto_ecdsa_pubkey_encode(ec, raw, &raw_len, pub, 0);

  if (!EC_KEY_oct2key(key, raw, raw_len, ec->ctx))
    goto fail;

  return key;

fail:
  if (key != NULL)
    EC_KEY_free(key);

  return NULL;
}

static int
bcrypto_ecdsa_pubkey_from_ec_key(bcrypto_ecdsa_t *ec,
                                 bcrypto_ecdsa_pubkey_t *pub,
                                 const EC_KEY *key) {
  const EC_POINT *point = NULL;
  point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
  uint8_t *raw = NULL;
  int raw_len = 0;

  point = EC_KEY_get0_public_key(key);
  assert(point != NULL);

  if (EC_POINT_is_at_infinity(ec->group, point))
    return 0;

  raw_len = EC_KEY_key2buf(key, form, &raw, ec->ctx);

  if (raw_len <= 0)
    return 0;

  assert((size_t)raw_len == 1 + ec->size * 2);
  assert(raw[0] == 0x04);

  memcpy(&pub->x[0], &raw[1], ec->size);
  memcpy(&pub->y[0], &raw[1 + ec->size], ec->size);

  OPENSSL_free(raw);

  return 1;
}

static int
bcrypto_ecdsa_pubkey_from_ec_point(bcrypto_ecdsa_t *ec,
                                   bcrypto_ecdsa_pubkey_t *pub,
                                   const EC_POINT *point) {
  point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
  uint8_t *raw = NULL;
  int raw_len = 0;

  if (EC_POINT_is_at_infinity(ec->group, point))
    return 0;

  raw_len = EC_POINT_point2buf(ec->group, point, form, &raw, ec->ctx);

  if (raw_len <= 0)
    return 0;

  assert((size_t)raw_len == 1 + ec->size * 2);
  assert(raw[0] == 0x04);

  memcpy(&pub->x[0], &raw[1], ec->size);
  memcpy(&pub->y[0], &raw[1 + ec->size], ec->size);

  OPENSSL_free(raw);

  return 1;
}

static int
bcrypto_ecdsa_pubkey_equals(bcrypto_ecdsa_t *ec,
                            const bcrypto_ecdsa_pubkey_t *a,
                            const bcrypto_ecdsa_pubkey_t *b) {
  return memcmp(a->x, b->x, ec->size) == 0
      && memcmp(a->y, b->y, ec->size) == 0;
}

/*
 * Signature
 */

void
bcrypto_ecdsa_sig_encode(bcrypto_ecdsa_t *ec,
                         uint8_t *out,
                         const bcrypto_ecdsa_sig_t *sig) {
  memcpy(&out[0], &sig->r[0], ec->scalar_size);
  memcpy(&out[ec->scalar_size], &sig->s[0], ec->scalar_size);
}

int
bcrypto_ecdsa_sig_decode(bcrypto_ecdsa_t *ec,
                         bcrypto_ecdsa_sig_t *sig,
                         const uint8_t *raw) {
  memcpy(&sig->r[0], &raw[0], ec->scalar_size);
  memcpy(&sig->s[0], &raw[ec->scalar_size], ec->scalar_size);

  return memcmp(sig->r, ec->zero, ec->scalar_size) != 0
      && memcmp(sig->s, ec->zero, ec->scalar_size) != 0
      && memcmp(sig->r, ec->order, ec->scalar_size) < 0
      && memcmp(sig->s, ec->order, ec->scalar_size) < 0;
}

int
bcrypto_ecdsa_sig_encode_der(bcrypto_ecdsa_t *ec,
                             uint8_t *out,
                             size_t *out_len,
                             const bcrypto_ecdsa_sig_t *sig) {
  assert(ec->scalar_size < 0x7d);

  uint8_t r[1 + BCRYPTO_ECDSA_MAX_SCALAR_SIZE] = {0};
  uint8_t *rp = (uint8_t *)&sig->r[0];
  size_t rlen = ec->scalar_size;
  uint8_t s[1 + BCRYPTO_ECDSA_MAX_SCALAR_SIZE] = {0};
  uint8_t *sp = (uint8_t *)&sig->s[0];
  size_t slen = ec->scalar_size;

  while (rlen > 1 && rp[0] == 0)
    rlen--, rp++;

  while (slen > 1 && sp[0] == 0)
    slen--, sp++;

  size_t rn = (rp[0] & 0x80) ? 1 : 0;
  size_t sn = (sp[0] & 0x80) ? 1 : 0;

  memcpy(r + rn, rp, rlen);
  memcpy(s + sn, sp, slen);

  rlen += rn;
  slen += sn;

  size_t seq = 2 + rlen + 2 + slen;
  size_t wide = seq >= 0x80 ? 1 : 0;
  size_t len = 2 + wide + seq;

  if (len > *out_len)
    return 0;

  *(out++) = 0x30;

  if (wide)
    *(out++) = 0x81;

  *(out++) = seq;
  *(out++) = 0x02;
  *(out++) = rlen;

  memcpy(out, r, rlen);
  out += rlen;

  *(out++) = 0x02;
  *(out++) = slen;

  memcpy(out, s, slen);
  out += slen;

  *out_len = len;

  return 1;
}

int
bcrypto_ecdsa_sig_decode_der(bcrypto_ecdsa_t *ec,
                             bcrypto_ecdsa_sig_t *sig,
                             const uint8_t *raw,
                             size_t raw_len) {
  size_t rpos, rlen, spos, slen;
  size_t pos = 0;
  size_t lenbyte;
  int overflow = 0;

  memset(sig->r, 0x00, ec->scalar_size);
  memset(sig->s, 0x00, ec->scalar_size);

  /* Sequence tag byte */
  if (pos == raw_len || raw[pos] != 0x30)
    return 0;

  pos++;

  /* Sequence length bytes */
  if (pos == raw_len)
    return 0;

  lenbyte = raw[pos++];

  if (lenbyte & 0x80) {
    lenbyte -= 0x80;

    if (pos + lenbyte > raw_len)
      return 0;

    pos += lenbyte;
  }

  /* Integer tag byte for R */
  if (pos == raw_len || raw[pos] != 0x02)
    return 0;

  pos++;

  /* Integer length for R */
  if (pos == raw_len)
    return 0;

  lenbyte = raw[pos++];

  if (lenbyte & 0x80) {
    lenbyte -= 0x80;

    if (pos + lenbyte > raw_len)
      return 0;

    while (lenbyte > 0 && raw[pos] == 0) {
      pos++;
      lenbyte--;
    }

    if (lenbyte >= sizeof(size_t))
      return 0;

    rlen = 0;

    while (lenbyte > 0) {
      rlen = (rlen << 8) + raw[pos];
      pos++;
      lenbyte--;
    }
  } else {
    rlen = lenbyte;
  }

  if (rlen > raw_len - pos)
    return 0;

  rpos = pos;
  pos += rlen;

  /* Integer tag byte for S */
  if (pos == raw_len || raw[pos] != 0x02)
    return 0;

  pos++;

  /* Integer length for S */
  if (pos == raw_len)
    return 0;

  lenbyte = raw[pos++];

  if (lenbyte & 0x80) {
    lenbyte -= 0x80;

    if (pos + lenbyte > raw_len)
      return 0;

    while (lenbyte > 0 && raw[pos] == 0) {
      pos++;
      lenbyte--;
    }

    if (lenbyte >= sizeof(size_t))
      return 0;

    slen = 0;

    while (lenbyte > 0) {
      slen = (slen << 8) + raw[pos];
      pos++;
      lenbyte--;
    }
  } else {
    slen = lenbyte;
  }

  if (slen > raw_len - pos)
    return 0;

  spos = pos;
  pos += slen;

  /* Ignore leading zeroes in R */
  while (rlen > 0 && raw[rpos] == 0) {
    rlen--;
    rpos++;
  }

  /* Copy R value */
  if (rlen > ec->scalar_size)
    overflow = 1;
  else
    memcpy(sig->r + ec->scalar_size - rlen, raw + rpos, rlen);

  /* Ignore leading zeroes in S */
  while (slen > 0 && raw[spos] == 0) {
    slen--;
    spos++;
  }

  /* Copy S value */
  if (slen > ec->scalar_size)
    overflow = 1;
  else
    memcpy(sig->s + ec->scalar_size - slen, raw + spos, slen);

  if (!overflow) {
    overflow = memcmp(sig->r, ec->order, ec->scalar_size) >= 0
            || memcmp(sig->s, ec->order, ec->scalar_size) >= 0;
  }

  if (overflow) {
    memset(sig->r, 0x00, ec->scalar_size);
    memset(sig->s, 0x00, ec->scalar_size);
  }

  return 1;
}

static ECDSA_SIG *
bcrypto_ecdsa_sig_to_ecdsa_sig(bcrypto_ecdsa_t *ec,
                               const bcrypto_ecdsa_sig_t *sig) {
  ECDSA_SIG *sig_ec = NULL;
  BIGNUM *r_bn = NULL;
  BIGNUM *s_bn = NULL;

  sig_ec = ECDSA_SIG_new();

  if (sig_ec == NULL)
    goto fail;

  r_bn = BN_bin2bn(sig->r, ec->scalar_size, NULL);

  if (r_bn == NULL)
    goto fail;

  s_bn = BN_bin2bn(sig->s, ec->scalar_size, NULL);

  if (s_bn == NULL)
    goto fail;

  if (BN_is_zero(r_bn) || BN_cmp(r_bn, ec->n) >= 0)
    goto fail;

  if (BN_is_zero(s_bn) || BN_cmp(s_bn, ec->n) >= 0)
    goto fail;

  if (!ECDSA_SIG_set0(sig_ec, r_bn, s_bn))
    goto fail;

  return sig_ec;

fail:
  if (sig_ec != NULL)
    ECDSA_SIG_free(sig_ec);

  if (r_bn != NULL)
    BN_free(r_bn);

  if (s_bn != NULL)
    BN_free(s_bn);

  return NULL;
}

static void
bcrypto_ecdsa_sig_from_ecdsa_sig(
  bcrypto_ecdsa_t *ec,
  bcrypto_ecdsa_sig_t *sig,
  const ECDSA_SIG *sig_ec
) {
  const BIGNUM *r_bn = NULL;
  const BIGNUM *s_bn = NULL;

  ECDSA_SIG_get0(sig_ec, &r_bn, &s_bn);
  assert(r_bn != NULL && s_bn != NULL);

  assert((size_t)BN_num_bytes(r_bn) <= ec->scalar_size);
  assert((size_t)BN_num_bytes(s_bn) <= ec->scalar_size);

  assert(BN_bn2binpad(r_bn, sig->r, ec->scalar_size) > 0);
  assert(BN_bn2binpad(s_bn, sig->s, ec->scalar_size) > 0);
}

void
bcrypto_ecdsa_sig_normalize(bcrypto_ecdsa_t *ec,
                            bcrypto_ecdsa_sig_t *out,
                            const bcrypto_ecdsa_sig_t *sig) {
  if (out != sig)
    memcpy(out, sig, sizeof(bcrypto_ecdsa_sig_t));

  if (memcmp(out->s, ec->half, ec->scalar_size) > 0) {
    int carry = 0;
    int i, r;

    for (i = ec->scalar_size - 1; i >= 0; i--) {
      r = (int)ec->order[i] - (int)out->s[i] + carry;
      carry = r >> 8;
      out->s[i] = r & 0xff;
    }
  }
}

int
bcrypto_ecdsa_sig_is_low_s(bcrypto_ecdsa_t *ec,
                           const bcrypto_ecdsa_sig_t *sig) {
  return memcmp(sig->s, ec->zero, ec->scalar_size) != 0
      && memcmp(sig->s, ec->half, ec->scalar_size) <= 0;
}

/*
 * ECDSA
 */

int
bcrypto_ecdsa_init(bcrypto_ecdsa_t *ec, const char *name) {
  assert(ec != NULL && name != NULL);
  memset(ec, 0x00, sizeof(bcrypto_ecdsa_t));

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    return 0;

  EC_KEY *key = EC_KEY_new_by_curve_name(type);

  if (key == NULL)
    return 0;

  ec->initialized = 1;
  ec->type = type;

  ec->ctx = BN_CTX_new();
  assert(ec->ctx != NULL);

  ec->key = key;

  ec->group = EC_KEY_get0_group(ec->key);
  assert(ec->group != NULL);

  ec->bits = (size_t)EC_GROUP_get_degree(ec->group);
  ec->size = (ec->bits + 7) / 8;
  assert(ec->size <= BCRYPTO_ECDSA_MAX_FIELD_SIZE);

  ec->n = BN_new();
  ec->nh = BN_new();
  ec->p = BN_new();
  ec->a = BN_new();
  ec->b = BN_new();

  assert(ec->n != NULL);
  assert(ec->nh != NULL);
  assert(ec->p != NULL);
  assert(ec->a != NULL);
  assert(ec->b != NULL);

  assert(EC_GROUP_get_order(ec->group, ec->n, ec->ctx) != 0);
  assert(BN_rshift1(ec->nh, ec->n) != 0);

#if OPENSSL_VERSION_NUMBER >= 0x10200000L
  assert(EC_GROUP_get_curve(ec->group, ec->p, ec->a, ec->b, ec->ctx) != 0);
#else
  assert(EC_GROUP_get_curve_GFp(ec->group, ec->p, ec->a, ec->b, ec->ctx) != 0);
#endif

  ec->g = EC_GROUP_get0_generator(ec->group);
  assert(ec->g != NULL);

  ec->scalar_bits = (size_t)BN_num_bits(ec->n);
  ec->scalar_size = (ec->scalar_bits + 7) >> 3;
  ec->sig_size = ec->scalar_size * 2;
  assert(ec->scalar_size <= BCRYPTO_ECDSA_MAX_SCALAR_SIZE);

  memset(&ec->zero[0], 0x00, ec->scalar_size);
  assert(BN_bn2binpad(ec->n, &ec->order[0], ec->scalar_size) > 0);
  assert(BN_bn2binpad(ec->nh, &ec->half[0], ec->scalar_size) > 0);

  return 1;
}

void
bcrypto_ecdsa_uninit(bcrypto_ecdsa_t *ec) {
  assert(ec != NULL);

  if (!ec->initialized)
    return;

  BN_CTX_free(ec->ctx);
  EC_KEY_free(ec->key);
  BN_free(ec->n);
  BN_free(ec->nh);
  BN_free(ec->p);
  BN_free(ec->a);
  BN_free(ec->b);

  ec->initialized = 0;
  ec->ctx = NULL;
  ec->key = NULL;
  ec->group = NULL;
  ec->n = NULL;
  ec->nh = NULL;
  ec->p = NULL;
  ec->a = NULL;
  ec->b = NULL;
  ec->g = NULL;
}

int
bcrypto_ecdsa_privkey_generate(bcrypto_ecdsa_t *ec, uint8_t *priv) {
  do {
    if (!bcrypto_random(priv, ec->scalar_size))
      return 0;
  } while (!bcrypto_ecdsa_valid_scalar(ec, priv));

  return 1;
}

int
bcrypto_ecdsa_privkey_verify(bcrypto_ecdsa_t *ec, const uint8_t *priv) {
  return bcrypto_ecdsa_valid_scalar(ec, priv);
}

static int
bcrypto_ecdsa_privkey_export_inner(bcrypto_ecdsa_t *ec,
                                   uint8_t **out,
                                   size_t *out_len,
                                   const uint8_t *priv,
                                   int compress,
                                   int no_params) {
  EC_KEY *priv_ec = NULL;
  EC_POINT *pub_point = NULL;

  if (!bcrypto_ecdsa_valid_scalar(ec, priv))
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(ec->type);

  if (priv_ec == NULL)
    goto fail;

  if (!EC_KEY_oct2priv(priv_ec, priv, ec->scalar_size))
    goto fail;

  const BIGNUM *priv_bn = EC_KEY_get0_private_key(priv_ec);
  assert(priv_bn != NULL);

  pub_point = EC_POINT_new(ec->group);

  if (pub_point == NULL)
    goto fail;

  if (!EC_POINT_mul(ec->group, pub_point, priv_bn, NULL, NULL, ec->ctx))
    goto fail;

  if (!EC_KEY_set_public_key(priv_ec, pub_point))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  EC_KEY_set_conv_form(priv_ec, form);

  if (no_params) {
    EC_KEY_set_enc_flags(priv_ec,
      EC_KEY_get_enc_flags(priv_ec) | EC_PKEY_NO_PARAMETERS);
  }

  EC_KEY_set_asn1_flag(priv_ec, OPENSSL_EC_NAMED_CURVE);

  uint8_t *buf = NULL;
  int len = i2d_ECPrivateKey(priv_ec, &buf);

  if (len <= 0)
    goto fail;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = (size_t)len;

  EC_KEY_free(priv_ec);
  EC_POINT_free(pub_point);

  return 1;

fail:
  if (priv_ec != NULL)
    EC_KEY_free(priv_ec);

  if (pub_point != NULL)
    EC_POINT_free(pub_point);

  return 0;
}

int
bcrypto_ecdsa_privkey_export(bcrypto_ecdsa_t *ec,
                             uint8_t **out,
                             size_t *out_len,
                             const uint8_t *priv,
                             int compress) {
  return bcrypto_ecdsa_privkey_export_inner(ec, out, out_len,
                                            priv, compress, 0);
}

int
bcrypto_ecdsa_privkey_import(bcrypto_ecdsa_t *ec,
                             uint8_t *out,
                             const uint8_t *raw,
                             size_t raw_len) {
  EC_KEY *priv_ec = NULL;

  priv_ec = EC_KEY_new_by_curve_name(ec->type);

  if (priv_ec == NULL)
    goto fail;

  EC_KEY_set_asn1_flag(priv_ec, OPENSSL_EC_NAMED_CURVE);

  const uint8_t *p = raw;

  if (d2i_ECPrivateKey(&priv_ec, &p, raw_len) == NULL)
    goto fail;

  const BIGNUM *priv_bn = EC_KEY_get0_private_key(priv_ec);
  assert(priv_bn != NULL);

  assert((size_t)BN_num_bytes(priv_bn) <= ec->scalar_size);

  assert(BN_bn2binpad(priv_bn, out, ec->scalar_size) > 0);

  if (!bcrypto_ecdsa_valid_scalar(ec, out))
    goto fail;

  EC_KEY_free(priv_ec);

  return 1;

fail:
  if (priv_ec != NULL)
    EC_KEY_free(priv_ec);

  return 0;
}

int
bcrypto_ecdsa_privkey_export_pkcs8(bcrypto_ecdsa_t *ec,
                                   uint8_t **out,
                                   size_t *out_len,
                                   const uint8_t *priv,
                                   int compress) {
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/ec/ec_ameth.c#L217 */
  uint8_t *ep = NULL;
  size_t eplen = 0;
  PKCS8_PRIV_KEY_INFO *p8 = NULL;

  if (!bcrypto_ecdsa_privkey_export_inner(ec, &ep, &eplen,
                                          priv, compress, 1)) {
    goto fail;
  }

  p8 = PKCS8_PRIV_KEY_INFO_new();

  if (p8 == NULL)
    goto fail;

  if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_X9_62_id_ecPublicKey), 0,
                       V_ASN1_OBJECT, OBJ_nid2obj(ec->type), ep, (int)eplen)) {
    goto fail;
  }

  ep = NULL;

  uint8_t *buf = NULL;
  int len = i2d_PKCS8_PRIV_KEY_INFO(p8, &buf);

  if (len <= 0)
    goto fail;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = (size_t)len;

  PKCS8_PRIV_KEY_INFO_free(p8);

  return 1;

fail:
  if (ep != NULL)
    OPENSSL_free(ep);

  if (p8 != NULL)
    PKCS8_PRIV_KEY_INFO_free(p8);

  return 0;
}

int
bcrypto_ecdsa_privkey_import_pkcs8(bcrypto_ecdsa_t *ec,
                                   uint8_t *out,
                                   const uint8_t *raw,
                                   size_t raw_len) {
  /* https://github.com/openssl/openssl/blob/32f803d/crypto/ec/ec_ameth.c#L184 */
  PKCS8_PRIV_KEY_INFO *p8 = NULL;
  const unsigned char *p = NULL;
  const void *pval;
  int ptype, pklen;
  const X509_ALGOR *palg;
  const ASN1_OBJECT *palgoid;

  const uint8_t *pp = raw;

  if (d2i_PKCS8_PRIV_KEY_INFO(&p8, &pp, raw_len) == NULL)
    goto fail;

  if (!PKCS8_pkey_get0(NULL, &p, &pklen, &palg, p8))
    goto fail;

  X509_ALGOR_get0(&palgoid, &ptype, &pval, palg);

  if (OBJ_obj2nid(palgoid) != NID_X9_62_id_ecPublicKey)
    goto fail;

  if (ptype == V_ASN1_OBJECT) {
    if (OBJ_obj2nid(pval) != ec->type)
      goto fail;
  } else if (ptype != V_ASN1_UNDEF && ptype != V_ASN1_NULL) {
    goto fail;
  }

  if (!bcrypto_ecdsa_privkey_import(ec, out, p, pklen))
    goto fail;

  PKCS8_PRIV_KEY_INFO_free(p8);

  return 1;

fail:
  if (p8 != NULL)
    PKCS8_PRIV_KEY_INFO_free(p8);

  return 0;
}

int
bcrypto_ecdsa_privkey_tweak_add(bcrypto_ecdsa_t *ec,
                                uint8_t *out,
                                const uint8_t *priv,
                                const uint8_t *tweak) {
  BIGNUM *priv_bn = NULL;
  BIGNUM *tweak_bn = NULL;

  priv_bn = BN_bin2bn(priv, ec->scalar_size, NULL);

  if (priv_bn == NULL)
    goto fail;

  if (BN_is_zero(priv_bn) || BN_ucmp(priv_bn, ec->n) >= 0)
    goto fail;

  tweak_bn = BN_bin2bn(tweak, ec->scalar_size, NULL);

  if (tweak_bn == NULL)
    goto fail;

  if (BN_ucmp(tweak_bn, ec->n) >= 0)
    goto fail;

  if (!BN_mod_add(priv_bn, priv_bn, tweak_bn, ec->n, ec->ctx))
    goto fail;

  if (BN_is_zero(priv_bn))
    goto fail;

  assert((size_t)BN_num_bytes(priv_bn) <= ec->scalar_size);

  assert(BN_bn2binpad(priv_bn, out, ec->scalar_size) > 0);

  BN_clear_free(priv_bn);
  BN_clear_free(tweak_bn);

  return 1;

fail:
  if (priv_bn != NULL)
    BN_clear_free(priv_bn);

  if (tweak_bn != NULL)
    BN_clear_free(tweak_bn);

  return 0;
}

int
bcrypto_ecdsa_privkey_tweak_mul(bcrypto_ecdsa_t *ec,
                                uint8_t *out,
                                const uint8_t *priv,
                                const uint8_t *tweak) {
  BIGNUM *priv_bn = NULL;
  BIGNUM *tweak_bn = NULL;

  priv_bn = BN_bin2bn(priv, ec->scalar_size, NULL);

  if (priv_bn == NULL)
    goto fail;

  if (BN_is_zero(priv_bn) || BN_cmp(priv_bn, ec->n) >= 0)
    goto fail;

  tweak_bn = BN_bin2bn(tweak, ec->scalar_size, NULL);

  if (tweak_bn == NULL)
    goto fail;

  if (BN_is_zero(tweak_bn) || BN_cmp(tweak_bn, ec->n) >= 0)
    goto fail;

  if (!BN_mod_mul(priv_bn, priv_bn, tweak_bn, ec->n, ec->ctx))
    goto fail;

  if (BN_is_zero(priv_bn))
    goto fail;

  assert((size_t)BN_num_bytes(priv_bn) <= ec->scalar_size);

  assert(BN_bn2binpad(priv_bn, out, ec->scalar_size) > 0);

  BN_clear_free(priv_bn);
  BN_clear_free(tweak_bn);

  return 1;

fail:
  if (priv_bn != NULL)
    BN_clear_free(priv_bn);

  if (tweak_bn != NULL)
    BN_clear_free(tweak_bn);

  return 0;
}

int
bcrypto_ecdsa_privkey_mod(bcrypto_ecdsa_t *ec,
                          uint8_t *out,
                          const uint8_t *priv,
                          size_t priv_len) {
  BIGNUM *priv_bn = NULL;

  if (priv_len > ec->scalar_size) {
    priv = &priv[priv_len - ec->scalar_size];
    priv_len = ec->scalar_size;
  }

  priv_bn = BN_bin2bn(priv, priv_len, NULL);

  if (priv_bn == NULL)
    goto fail;

  if (!BN_mod(priv_bn, priv_bn, ec->n, ec->ctx))
    goto fail;

  assert((size_t)BN_num_bytes(priv_bn) <= ec->scalar_size);

  assert(BN_bn2binpad(priv_bn, out, ec->scalar_size) > 0);

  BN_clear_free(priv_bn);

  return 1;

fail:
  if (priv_bn != NULL)
    BN_clear_free(priv_bn);

  return 0;
}

int
bcrypto_ecdsa_privkey_negate(bcrypto_ecdsa_t *ec,
                             uint8_t *out,
                             const uint8_t *priv) {
  BIGNUM *priv_bn = NULL;

  priv_bn = BN_bin2bn(priv, ec->scalar_size, NULL);

  if (priv_bn == NULL)
    goto fail;

  if (BN_cmp(priv_bn, ec->n) >= 0)
    goto fail;

  if (!BN_mod_sub(priv_bn, ec->n, priv_bn, ec->n, ec->ctx))
    goto fail;

  assert((size_t)BN_num_bytes(priv_bn) <= ec->scalar_size);

  assert(BN_bn2binpad(priv_bn, out, ec->scalar_size) > 0);

  BN_clear_free(priv_bn);

  return 1;

fail:
  if (priv_bn != NULL)
    BN_clear_free(priv_bn);

  return 0;
}

int
bcrypto_ecdsa_privkey_inverse(bcrypto_ecdsa_t *ec,
                              uint8_t *out,
                              const uint8_t *priv) {
  BIGNUM *priv_bn = NULL;

  priv_bn = BN_bin2bn(priv, ec->scalar_size, NULL);

  if (priv_bn == NULL)
    goto fail;

  if (BN_is_zero(priv_bn) || BN_cmp(priv_bn, ec->n) >= 0)
    goto fail;

  if (!BN_mod_inverse(priv_bn, priv_bn, ec->n, ec->ctx))
    goto fail;

  if (BN_is_zero(priv_bn))
    goto fail;

  assert((size_t)BN_num_bytes(priv_bn) <= ec->scalar_size);

  assert(BN_bn2binpad(priv_bn, out, ec->scalar_size) > 0);

  BN_clear_free(priv_bn);

  return 1;

fail:
  if (priv_bn != NULL)
    BN_clear_free(priv_bn);

  return 0;
}

int
bcrypto_ecdsa_pubkey_create(bcrypto_ecdsa_t *ec,
                            bcrypto_ecdsa_pubkey_t *pub,
                            const uint8_t *priv) {
  BIGNUM *priv_bn = NULL;
  EC_POINT *pub_point = NULL;

  priv_bn = BN_bin2bn(priv, ec->scalar_size, NULL);

  if (priv_bn == NULL)
    goto fail;

  if (BN_is_zero(priv_bn) || BN_cmp(priv_bn, ec->n) >= 0)
    goto fail;

  pub_point = EC_POINT_new(ec->group);

  if (pub_point == NULL)
    goto fail;

  if (!EC_POINT_mul(ec->group, pub_point, priv_bn, NULL, NULL, ec->ctx))
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, pub, pub_point))
    goto fail;

  BN_free(priv_bn);
  EC_POINT_free(pub_point);

  return 1;

fail:
  if (priv_bn != NULL)
    BN_free(priv_bn);

  if (pub_point != NULL)
    EC_POINT_free(pub_point);

  return 0;
}

int
bcrypto_ecdsa_pubkey_export_spki(bcrypto_ecdsa_t *ec,
                                 uint8_t **out,
                                 size_t *out_len,
                                 const bcrypto_ecdsa_pubkey_t *pub,
                                 int compress) {
  EC_KEY *pub_ec = NULL;
  uint8_t *buf = NULL;
  int len = 0;

  pub_ec = bcrypto_ecdsa_pubkey_to_ec_key(ec, pub);

  if (pub_ec == NULL)
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  EC_KEY_set_conv_form(pub_ec, form);
  EC_KEY_set_asn1_flag(pub_ec, OPENSSL_EC_NAMED_CURVE);

  len = i2d_EC_PUBKEY(pub_ec, &buf);

  if (len <= 0)
    goto fail;

  FIX_BORINGSSL(buf, len);

  *out = buf;
  *out_len = (size_t)len;

  EC_KEY_free(pub_ec);

  return 1;

fail:
  if (pub_ec != NULL)
    EC_KEY_free(pub_ec);

  return 0;
}

int
bcrypto_ecdsa_pubkey_import_spki(bcrypto_ecdsa_t *ec,
                                 bcrypto_ecdsa_pubkey_t *out,
                                 const uint8_t *raw,
                                 size_t raw_len) {
  EC_KEY *pub_ec = NULL;

  pub_ec = EC_KEY_new_by_curve_name(ec->type);

  if (pub_ec == NULL)
    goto fail;

  EC_KEY_set_asn1_flag(pub_ec, OPENSSL_EC_NAMED_CURVE);

  const uint8_t *p = raw;

  if (d2i_EC_PUBKEY(&pub_ec, &p, raw_len) == NULL)
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_key(ec, out, pub_ec))
    goto fail;

  EC_KEY_free(pub_ec);

  return 1;

fail:
  if (pub_ec != NULL)
    EC_KEY_free(pub_ec);

  return 0;
}

int
bcrypto_ecdsa_pubkey_tweak_add(bcrypto_ecdsa_t *ec,
                               bcrypto_ecdsa_pubkey_t *out,
                               const bcrypto_ecdsa_pubkey_t *pub,
                               const uint8_t *tweak) {
  EC_KEY *pub_ec = NULL;
  BIGNUM *tweak_bn = NULL;
  EC_POINT *tweak_point = NULL;
  const EC_POINT *key_point = NULL;

  pub_ec = bcrypto_ecdsa_pubkey_to_ec_key(ec, pub);

  if (pub_ec == NULL)
    goto fail;

  tweak_bn = BN_bin2bn(tweak, ec->scalar_size, NULL);

  if (tweak_bn == NULL)
    goto fail;

  if (BN_ucmp(tweak_bn, ec->n) >= 0)
    goto fail;

  tweak_point = EC_POINT_new(ec->group);

  if (tweak_point == NULL)
    goto fail;

  if (!EC_POINT_mul(ec->group, tweak_point, tweak_bn, NULL, NULL, ec->ctx))
    goto fail;

  key_point = EC_KEY_get0_public_key(pub_ec);
  assert(key_point != NULL);

  if (!EC_POINT_add(ec->group, tweak_point, key_point, tweak_point, ec->ctx))
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, out, tweak_point))
    goto fail;

  EC_KEY_free(pub_ec);
  BN_clear_free(tweak_bn);
  EC_POINT_free(tweak_point);

  return 1;

fail:
  if (pub_ec != NULL)
    EC_KEY_free(pub_ec);

  if (tweak_bn != NULL)
    BN_clear_free(tweak_bn);

  if (tweak_point != NULL)
    EC_POINT_free(tweak_point);

  return 0;
}

int
bcrypto_ecdsa_pubkey_tweak_mul(bcrypto_ecdsa_t *ec,
                               bcrypto_ecdsa_pubkey_t *out,
                               const bcrypto_ecdsa_pubkey_t *pub,
                               const uint8_t *tweak) {
  return bcrypto_ecdsa_derive(ec, out, pub, tweak);
}

int
bcrypto_ecdsa_pubkey_add(bcrypto_ecdsa_t *ec,
                         bcrypto_ecdsa_pubkey_t *out,
                         const bcrypto_ecdsa_pubkey_t *pub1,
                         const bcrypto_ecdsa_pubkey_t *pub2) {
  EC_KEY *pub1_ec = NULL;
  EC_KEY *pub2_ec = NULL;
  const EC_POINT *point1 = NULL;
  const EC_POINT *point2 = NULL;
  EC_POINT *result = NULL;

  pub1_ec = bcrypto_ecdsa_pubkey_to_ec_key(ec, pub1);

  if (pub1_ec == NULL)
    goto fail;

  pub2_ec = bcrypto_ecdsa_pubkey_to_ec_key(ec, pub2);

  if (pub2_ec == NULL)
    goto fail;

  point1 = EC_KEY_get0_public_key(pub1_ec);
  assert(point1 != NULL);

  point2 = EC_KEY_get0_public_key(pub2_ec);
  assert(point2 != NULL);

  result = EC_POINT_new(ec->group);

  if (result == NULL)
    goto fail;

  if (!EC_POINT_add(ec->group, result, point1, point2, ec->ctx))
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, out, result))
    goto fail;

  EC_KEY_free(pub1_ec);
  EC_KEY_free(pub2_ec);
  EC_POINT_free(result);

  return 1;

fail:
  if (pub1_ec != NULL)
    EC_KEY_free(pub1_ec);

  if (pub2_ec != NULL)
    EC_KEY_free(pub2_ec);

  if (result != NULL)
    EC_POINT_free(result);

  return 0;
}

int
bcrypto_ecdsa_pubkey_negate(bcrypto_ecdsa_t *ec,
                            bcrypto_ecdsa_pubkey_t *out,
                            const bcrypto_ecdsa_pubkey_t *pub) {
  EC_KEY *pub_ec = NULL;
  const EC_POINT *key_point = NULL;
  EC_POINT *neg_point = NULL;

  pub_ec = bcrypto_ecdsa_pubkey_to_ec_key(ec, pub);

  if (pub_ec == NULL)
    goto fail;

  key_point = EC_KEY_get0_public_key(pub_ec);
  assert(key_point != NULL);

  neg_point = EC_POINT_new(ec->group);

  if (neg_point == NULL)
    goto fail;

  if (!EC_POINT_copy(neg_point, key_point))
    goto fail;

  if (!EC_POINT_invert(ec->group, neg_point, ec->ctx))
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, out, neg_point))
    goto fail;

  EC_KEY_free(pub_ec);
  EC_POINT_free(neg_point);

  return 1;

fail:
  if (pub_ec != NULL)
    EC_KEY_free(pub_ec);

  if (neg_point != NULL)
    EC_POINT_free(neg_point);

  return 0;
}

int
bcrypto_ecdsa_sign(bcrypto_ecdsa_t *ec,
                   bcrypto_ecdsa_sig_t *sig,
                   const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *priv) {
  EC_KEY *priv_ec = NULL;
  ECDSA_SIG *sig_ec = NULL;

  if (!bcrypto_ecdsa_valid_scalar(ec, priv))
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(ec->type);

  if (priv_ec == NULL)
    goto fail;

  if (!EC_KEY_oct2priv(priv_ec, priv, ec->scalar_size))
    goto fail;

  bcrypto_poll();

  sig_ec = ECDSA_do_sign(msg, msg_len, priv_ec);

  if (sig_ec == NULL)
    goto fail;

  bcrypto_ecdsa_sig_from_ecdsa_sig(ec, sig, sig_ec);

  bcrypto_ecdsa_sig_normalize(ec, sig, sig);

  EC_KEY_free(priv_ec);
  ECDSA_SIG_free(sig_ec);

  return 1;

fail:
  if (priv_ec != NULL)
    EC_KEY_free(priv_ec);

  if (sig_ec != NULL)
    ECDSA_SIG_free(sig_ec);

  return 0;
}

int
bcrypto_ecdsa_sign_recoverable(bcrypto_ecdsa_t *ec,
                               bcrypto_ecdsa_sig_t *sig,
                               const uint8_t *msg,
                               size_t msg_len,
                               const uint8_t *priv) {
  bcrypto_ecdsa_pubkey_t Q, Qprime;
  int i = 0;

  if (!bcrypto_ecdsa_sign(ec, sig, msg, msg_len, priv))
    return 0;

  if (!bcrypto_ecdsa_pubkey_create(ec, &Q, priv))
    return 0;

  for (; i < 4; i++) {
    if (!bcrypto_ecdsa_recover(ec, &Qprime, msg, msg_len, sig, i))
      continue;

    if (!bcrypto_ecdsa_pubkey_equals(ec, &Q, &Qprime))
      continue;

    sig->param = i;

    return 1;
  }

  return 0;
}

int
bcrypto_ecdsa_verify(bcrypto_ecdsa_t *ec,
                     const uint8_t *msg,
                     size_t msg_len,
                     const bcrypto_ecdsa_sig_t *sig,
                     const bcrypto_ecdsa_pubkey_t *pub) {
  ECDSA_SIG *sig_ec = NULL;
  EC_KEY *pub_ec = NULL;

  sig_ec = bcrypto_ecdsa_sig_to_ecdsa_sig(ec, sig);

  if (sig_ec == NULL)
    goto fail;

  pub_ec = bcrypto_ecdsa_pubkey_to_ec_key(ec, pub);

  if (pub_ec == NULL)
    goto fail;

  if (ECDSA_do_verify(msg, msg_len, sig_ec, pub_ec) <= 0)
    goto fail;

  ECDSA_SIG_free(sig_ec);
  EC_KEY_free(pub_ec);

  return 1;

fail:
  if (sig_ec != NULL)
    ECDSA_SIG_free(sig_ec);

  if (pub_ec != NULL)
    EC_KEY_free(pub_ec);

  return 0;
}

int
bcrypto_ecdsa_recover(bcrypto_ecdsa_t *ec,
                      bcrypto_ecdsa_pubkey_t *pub,
                      const uint8_t *msg,
                      size_t msg_len,
                      const bcrypto_ecdsa_sig_t *sig,
                      int param) {
  EC_KEY *pub_ec = NULL;
  ECDSA_SIG *sig_ec = NULL;
  BIGNUM *x = NULL;
  EC_POINT *rp = NULL;
  BIGNUM *rinv = NULL;
  BIGNUM *s1 = NULL;
  BIGNUM *s2 = NULL;
  BIGNUM *e = NULL;
  EC_POINT *Q = NULL;

  if (param < 0 || (param & 3) != param)
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(ec->type);

  if (pub_ec == NULL)
    goto fail;

  sig_ec = bcrypto_ecdsa_sig_to_ecdsa_sig(ec, sig);

  if (sig_ec == NULL)
    goto fail;

  int y_odd = param & 1;
  int second_key = param >> 1;

  const BIGNUM *sig_r = NULL;
  const BIGNUM *sig_s = NULL;

  ECDSA_SIG_get0(sig_ec, &sig_r, &sig_s);
  assert(sig_r != NULL && sig_s != NULL);

  if (BN_is_zero(sig_r) || BN_cmp(sig_r, ec->n) >= 0)
    goto fail;

  if (BN_is_zero(sig_s) || BN_cmp(sig_s, ec->n) >= 0)
    goto fail;

  x = BN_new();

  if (x == NULL)
    goto fail;

  if (!BN_copy(x, sig_r))
    goto fail;

  if (second_key) {
    BIGNUM *m = BN_new();

    if (m == NULL)
      goto fail;

    if (!BN_mod(m, ec->p, ec->n, ec->ctx)) {
      BN_free(m);
      goto fail;
    }

    if (BN_cmp(sig_r, m) >= 0) {
      BN_free(m);
      goto fail;
    }

    BN_free(m);

    if (!BN_mod_add(x, x, ec->n, ec->p, ec->ctx))
      goto fail;
  }

  rp = EC_POINT_new(ec->group);

  if (rp == NULL)
    goto fail;

#if OPENSSL_VERSION_NUMBER >= 0x10200000L
  if (!EC_POINT_set_compressed_coordinates(ec->group, rp, x, y_odd, ec->ctx))
#else
  if (!EC_POINT_set_compressed_coordinates_GFp(ec->group, rp, x, y_odd, ec->ctx))
#endif
    goto fail;

  rinv = BN_new();

  if (rinv == NULL)
    goto fail;

  if (!BN_mod_inverse(rinv, sig_r, ec->n, ec->ctx))
    goto fail;

  if (msg_len > ec->scalar_size)
    msg_len = ec->scalar_size;

  e = BN_bin2bn(msg, msg_len, NULL);

  if (e == NULL)
    goto fail;

  int d = (int)msg_len * 8 - (int)ec->scalar_bits;

  if (d > 0) {
    if (!BN_rshift(e, e, d))
      goto fail;
  }

  if (!BN_mod(e, e, ec->n, ec->ctx))
    goto fail;

  s1 = BN_new();

  if (s1 == NULL)
    goto fail;

  if (!BN_mod_sub(s1, ec->n, e, ec->n, ec->ctx))
    goto fail;

  if (!BN_mod_mul(s1, s1, rinv, ec->n, ec->ctx))
    goto fail;

  s2 = BN_new();

  if (s2 == NULL)
    goto fail;

  if (!BN_mod_mul(s2, sig_s, rinv, ec->n, ec->ctx))
    goto fail;

  Q = EC_POINT_new(ec->group);

  if (Q == NULL)
    goto fail;

  if (!EC_POINT_mul(ec->group, Q, s1, rp, s2, ec->ctx))
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, pub, Q))
    goto fail;

  EC_KEY_free(pub_ec);
  ECDSA_SIG_free(sig_ec);
  BN_free(x);
  EC_POINT_free(rp);
  BN_free(rinv);
  BN_free(s1);
  BN_free(s2);
  BN_free(e);
  EC_POINT_free(Q);

  return 1;

fail:
  if (pub_ec != NULL)
    EC_KEY_free(pub_ec);

  if (sig_ec != NULL)
    ECDSA_SIG_free(sig_ec);

  if (x != NULL)
    BN_free(x);

  if (rp != NULL)
    EC_POINT_free(rp);

  if (rinv != NULL)
    BN_free(rinv);

  if (s1 != NULL)
    BN_free(s1);

  if (s2 != NULL)
    BN_free(s2);

  if (e != NULL)
    BN_free(e);

  if (Q != NULL)
    EC_POINT_free(Q);

  return 0;
}

int
bcrypto_ecdsa_derive(bcrypto_ecdsa_t *ec,
                     bcrypto_ecdsa_pubkey_t *out,
                     const bcrypto_ecdsa_pubkey_t *pub,
                     const uint8_t *priv) {
  BIGNUM *priv_bn = NULL;
  EC_KEY *pub_ec = NULL;
  EC_POINT *secret_point = NULL;
  const EC_POINT *pub_point = NULL;

  priv_bn = BN_bin2bn(priv, ec->scalar_size, NULL);

  if (priv_bn == NULL)
    goto fail;

  if (BN_is_zero(priv_bn) || BN_cmp(priv_bn, ec->n) >= 0)
    goto fail;

  pub_ec = bcrypto_ecdsa_pubkey_to_ec_key(ec, pub);

  if (pub_ec == NULL)
    goto fail;

  secret_point = EC_POINT_new(ec->group);

  if (secret_point == NULL)
    goto fail;

  pub_point = EC_KEY_get0_public_key(pub_ec);
  assert(pub_point != NULL);

  if (!EC_POINT_mul(ec->group, secret_point, NULL, pub_point, priv_bn, ec->ctx))
    goto fail;

  if (!bcrypto_ecdsa_pubkey_from_ec_point(ec, out, secret_point))
    goto fail;

  BN_free(priv_bn);
  EC_KEY_free(pub_ec);
  EC_POINT_free(secret_point);

  return 1;

fail:
  if (priv_bn != NULL)
    BN_free(priv_bn);

  if (pub_ec != NULL)
    EC_KEY_free(pub_ec);

  if (secret_point != NULL)
    EC_POINT_free(secret_point);

  return 0;
}

#endif
