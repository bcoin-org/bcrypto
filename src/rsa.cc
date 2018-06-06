#include <assert.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <string.h>

#include "rsa.h"

static RSA *
bc_rsa_generate(int bits) {
  RSA *key = NULL;
  BIGNUM *exp = NULL;

  key = RSA_new();

  if (!key)
    return NULL;

  exp = BN_new();

  if (!exp)
    goto fail;

  if (!BN_set_word(exp, 0x010001))
    goto fail;

  if (!RSA_generate_key_ex(key, bits, exp, NULL))
    goto fail;

  BN_free(exp);

  return key;

fail:
  if (key)
    RSA_free(key);

  if (exp)
    BN_free(exp);

  return NULL;
}

static int
bc_rsa_type(const char *alg) {
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
  // else if (strcmp(alg, "sha3") == 0)
  //   type = NID_sha3_256;

  return type;
}

static bool
bc_rsa_sign(
  int type,
  const uint8_t *m,
  size_t ml,
  RSA *key,
  uint8_t **s,
  size_t *sl
) {
  size_t siglen = RSA_size(key);
  uint8_t *sig = (uint8_t *)malloc(siglen * sizeof(uint8_t));

  if (!sig)
    return false;

  if (!RSA_sign(type, m, ml, sig, (unsigned int *)&siglen, key)) {
    free(sig);
    return false;
  }

  *s = sig;
  *sl = siglen;

  return true;
}

static bool
bc_rsa_validate(const RSA *key) {
  if (!RSA_check_key(key))
    return false;
  return true;
}

static bool
bc_rsa_verify(
  int type,
  const uint8_t *m,
  size_t ml,
  const uint8_t *s,
  size_t sl,
  RSA *key
) {
  if (!RSA_verify(type, m, ml, s, sl, key))
    return false;
  return true;
}

static RSA *
bc_rsa_sign_ctx(
  const uint8_t *nd,
  size_t nl,
  const uint8_t *ed,
  size_t el,
  const uint8_t *dd,
  size_t dl,
  const uint8_t *pd,
  size_t pl,
  const uint8_t *qd,
  size_t ql,
  const uint8_t *dpd,
  size_t dpl,
  const uint8_t *dqd,
  size_t dql,
  const uint8_t *qid,
  size_t qil
) {
  RSA *rsa = NULL;
  BIGNUM *n = NULL;
  BIGNUM *e = NULL;
  BIGNUM *d = NULL;
  BIGNUM *p = NULL;
  BIGNUM *q = NULL;
  BIGNUM *dp = NULL;
  BIGNUM *dq = NULL;
  BIGNUM *qi = NULL;

  rsa = RSA_new();

  if (!rsa)
    return NULL;

  n = BN_bin2bn(nd, nl, NULL);
  e = BN_bin2bn(ed, el, NULL);
  d = BN_bin2bn(dd, dl, NULL);
  p = BN_bin2bn(pd, pl, NULL);
  q = BN_bin2bn(qd, ql, NULL);
  dp = BN_bin2bn(dpd, dpl, NULL);
  dq = BN_bin2bn(dqd, dql, NULL);
  qi = BN_bin2bn(qid, qil, NULL);

  if (!n || !e || !d || !p || !q || !dp || !dq || !qi)
    goto fail;

  if (!RSA_set0_key(rsa, n, e, d))
    goto fail;

  n = NULL;
  e = NULL;
  d = NULL;

  if (!RSA_set0_factors(rsa, p, q))
    goto fail;

  p = NULL;
  q = NULL;

  if (!RSA_set0_crt_params(rsa, dp, dq, qi))
    goto fail;

  return rsa;

fail:
  if (rsa)
    RSA_free(rsa);

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
bc_rsa_verify_ctx(
  const uint8_t *nd,
  size_t nl,
  const uint8_t *ed,
  size_t el
) {
  RSA *rsa = NULL;
  BIGNUM *n = NULL;
  BIGNUM *e = NULL;

  rsa = RSA_new();

  if (!rsa)
    goto fail;

  n = BN_bin2bn(nd, nl, NULL);
  e = BN_bin2bn(ed, el, NULL);

  if (!n || !e)
    goto fail;

  if (!RSA_set0_key(rsa, n, e, NULL))
    goto fail;

  return rsa;

fail:
  if (rsa)
    RSA_free(rsa);

  if (n)
    BN_free(n);

  if (e)
    BN_free(e);

  return NULL;
}

static Nan::Persistent<v8::FunctionTemplate> rsa_constructor;

BRSA::BRSA() {}

BRSA::~BRSA() {}

void
BRSA::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BRSA::New);

  rsa_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("RSA").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetMethod(tpl, "privateKeyGenerate", BRSA::PrivateKeyGenerate);
  Nan::SetMethod(tpl, "sign", BRSA::Sign);
  Nan::SetMethod(tpl, "privateKeyVerify", BRSA::PrivateKeyVerify);
  Nan::SetMethod(tpl, "verify", BRSA::Verify);
  Nan::SetMethod(tpl, "publicKeyVerify", BRSA::PublicKeyVerify);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(rsa_constructor);

  target->Set(Nan::New("rsa").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BRSA::New) {
  return Nan::ThrowError("Could not create RSA instance.");
}

NAN_METHOD(BRSA::PrivateKeyGenerate) {
  if (info.Length() < 1)
    return Nan::ThrowError("rsa.privateKeyGenerate() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  uint32_t bits = info[0]->Uint32Value();

  RSA *key = bc_rsa_generate((int)bits);

  if (!key)
    return Nan::ThrowTypeError("Could not allocate context.");

  const BIGNUM *n = NULL;
  const BIGNUM *e = NULL;
  const BIGNUM *d = NULL;
  const BIGNUM *p = NULL;
  const BIGNUM *q = NULL;
  const BIGNUM *dp = NULL;
  const BIGNUM *dq = NULL;
  const BIGNUM *qi = NULL;

  RSA_get0_key(key, &n, &e, &d);
  RSA_get0_factors(key, &p, &q);
  RSA_get0_crt_params(key, &dp, &dq, &qi);

  assert(n && e && d && p && q && dp && dq && qi);

  size_t nl = BN_num_bytes(n);
  size_t el = BN_num_bytes(e);
  size_t dl = BN_num_bytes(d);
  size_t pl = BN_num_bytes(p);
  size_t ql = BN_num_bytes(q);
  size_t dpl = BN_num_bytes(dp);
  size_t dql = BN_num_bytes(dq);
  size_t qil = BN_num_bytes(qi);

  size_t s = nl + el + dl + pl + ql + dpl + dql + qil;
  uint8_t *arena = (uint8_t *)malloc(s * sizeof(uint8_t));

  if (!arena) {
    RSA_free(key);
    return Nan::ThrowTypeError("Could not allocate context.");
  }

  size_t pos = 0;
  uint8_t *nd = &arena[pos];
  pos += nl;
  uint8_t *ed = &arena[pos];
  pos += el;
  uint8_t *dd = &arena[pos];
  pos += dl;
  uint8_t *pd = &arena[pos];
  pos += pl;
  uint8_t *qd = &arena[pos];
  pos += ql;
  uint8_t *dpd = &arena[pos];
  pos += dpl;
  uint8_t *dqd = &arena[pos];
  pos += dql;
  uint8_t *qid = &arena[pos];
  pos += qil;

  assert(BN_bn2bin(n, nd) != 0);
  assert(BN_bn2bin(e, ed) != 0);
  assert(BN_bn2bin(d, dd) != 0);
  assert(BN_bn2bin(p, pd) != 0);
  assert(BN_bn2bin(q, qd) != 0);
  assert(BN_bn2bin(dp, dpd) != 0);
  assert(BN_bn2bin(dq, dqd) != 0);
  assert(BN_bn2bin(qi, qid) != 0);

  RSA_free(key);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  ret->Set(0, Nan::CopyBuffer((char *)&nd[0], nl).ToLocalChecked());
  ret->Set(1, Nan::CopyBuffer((char *)&ed[0], el).ToLocalChecked());
  ret->Set(2, Nan::CopyBuffer((char *)&dd[0], dl).ToLocalChecked());
  ret->Set(3, Nan::CopyBuffer((char *)&pd[0], pl).ToLocalChecked());
  ret->Set(4, Nan::CopyBuffer((char *)&qd[0], ql).ToLocalChecked());
  ret->Set(5, Nan::CopyBuffer((char *)&dpd[0], dpl).ToLocalChecked());
  ret->Set(6, Nan::CopyBuffer((char *)&dqd[0], dql).ToLocalChecked());
  ret->Set(7, Nan::CopyBuffer((char *)&qid[0], qil).ToLocalChecked());

  free(arena);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BRSA::Sign) {
  if (info.Length() < 10)
    return Nan::ThrowError("rsa.sign() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> dbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[6].As<v8::Object>();
  v8::Local<v8::Object> dpbuf = info[7].As<v8::Object>();
  v8::Local<v8::Object> dqbuf = info[8].As<v8::Object>();
  v8::Local<v8::Object> qibuf = info[9].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)
      || !node::Buffer::HasInstance(dbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(dpbuf)
      || !node::Buffer::HasInstance(dqbuf)
      || !node::Buffer::HasInstance(qibuf)) {
    // Yeah, fuck this.
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  const uint8_t *nd = (uint8_t *)node::Buffer::Data(nbuf);
  size_t nl = node::Buffer::Length(nbuf);

  const uint8_t *ed = (uint8_t *)node::Buffer::Data(ebuf);
  size_t el = node::Buffer::Length(ebuf);

  const uint8_t *dd = (uint8_t *)node::Buffer::Data(dbuf);
  size_t dl = node::Buffer::Length(dbuf);

  const uint8_t *pd = (uint8_t *)node::Buffer::Data(pbuf);
  size_t pl = node::Buffer::Length(pbuf);

  const uint8_t *qd = (uint8_t *)node::Buffer::Data(qbuf);
  size_t ql = node::Buffer::Length(qbuf);

  const uint8_t *dpd = (uint8_t *)node::Buffer::Data(dpbuf);
  size_t dpl = node::Buffer::Length(dpbuf);

  const uint8_t *dqd = (uint8_t *)node::Buffer::Data(dqbuf);
  size_t dql = node::Buffer::Length(dqbuf);

  const uint8_t *qid = (uint8_t *)node::Buffer::Data(qibuf);
  size_t qil = node::Buffer::Length(qibuf);

  if (!nd || !ed || !dd || !pd || !qd || !dpd || !dqd || !qid)
    return Nan::ThrowTypeError("Invalid parameters.");

  int type = bc_rsa_type(name);

  if (type == -1)
    return Nan::ThrowTypeError("Unknown algorithm.");

  RSA *key = bc_rsa_sign_ctx(
    nd, nl, ed, el, dd, dl, pd, pl, qd, ql, dpd, dpl, dqd, dql, qid, qil);

  if (!key)
    return Nan::ThrowTypeError("Could not allocate context.");

  uint8_t *s;
  size_t sl;

  bool result = bc_rsa_sign(type, md, ml, key, &s, &sl);

  RSA_free(key);

  if (!result)
    return Nan::ThrowTypeError("Could not allocate context.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)&s[0], sl).ToLocalChecked());
}

NAN_METHOD(BRSA::PrivateKeyVerify) {
  if (info.Length() < 8)
    return Nan::ThrowError("rsa.privateKeyVerify() requires arguments.");

  v8::Local<v8::Object> nbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> dbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> dpbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> dqbuf = info[6].As<v8::Object>();
  v8::Local<v8::Object> qibuf = info[7].As<v8::Object>();

  if (!node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)
      || !node::Buffer::HasInstance(dbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(dpbuf)
      || !node::Buffer::HasInstance(dqbuf)
      || !node::Buffer::HasInstance(qibuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *nd = (uint8_t *)node::Buffer::Data(nbuf);
  size_t nl = node::Buffer::Length(nbuf);

  const uint8_t *ed = (uint8_t *)node::Buffer::Data(ebuf);
  size_t el = node::Buffer::Length(ebuf);

  const uint8_t *dd = (uint8_t *)node::Buffer::Data(dbuf);
  size_t dl = node::Buffer::Length(dbuf);

  const uint8_t *pd = (uint8_t *)node::Buffer::Data(pbuf);
  size_t pl = node::Buffer::Length(pbuf);

  const uint8_t *qd = (uint8_t *)node::Buffer::Data(qbuf);
  size_t ql = node::Buffer::Length(qbuf);

  const uint8_t *dpd = (uint8_t *)node::Buffer::Data(dpbuf);
  size_t dpl = node::Buffer::Length(dpbuf);

  const uint8_t *dqd = (uint8_t *)node::Buffer::Data(dqbuf);
  size_t dql = node::Buffer::Length(dqbuf);

  const uint8_t *qid = (uint8_t *)node::Buffer::Data(qibuf);
  size_t qil = node::Buffer::Length(qibuf);

  if (!nd || !ed || !dd || !pd || !qd || !dpd || !dqd || !qid)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  RSA *key = bc_rsa_sign_ctx(
    nd, nl, ed, el, dd, dl, pd, pl, qd, ql, dpd, dpl, dqd, dql, qid, qil);

  if (!key)
    return Nan::ThrowTypeError("Could not allocate context.");

  bool result = bc_rsa_validate(key);

  RSA_free(key);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BRSA::Verify) {
  if (info.Length() < 5)
    return Nan::ThrowError("sha256.multi() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[4].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  const uint8_t *sd = (uint8_t *)node::Buffer::Data(sbuf);
  size_t sl = node::Buffer::Length(sbuf);

  const uint8_t *nd = (uint8_t *)node::Buffer::Data(nbuf);
  size_t nl = node::Buffer::Length(nbuf);

  const uint8_t *ed = (uint8_t *)node::Buffer::Data(ebuf);
  size_t el = node::Buffer::Length(ebuf);

  if (!sd || !nd || !ed)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int type = bc_rsa_type(name);

  if (type == -1)
    return Nan::ThrowTypeError("Unknown algorithm.");

  RSA *key = bc_rsa_verify_ctx(nd, nl, ed, el);

  if (!key)
    return Nan::ThrowTypeError("Could not allocate context.");

  bool result = bc_rsa_verify(type, md, ml, sd, sl, key);

  RSA_free(key);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BRSA::PublicKeyVerify) {
  if (info.Length() < 2)
    return Nan::ThrowError("rsa.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> nbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *nd = (uint8_t *)node::Buffer::Data(nbuf);
  size_t nl = node::Buffer::Length(nbuf);

  const uint8_t *ed = (uint8_t *)node::Buffer::Data(ebuf);
  size_t el = node::Buffer::Length(ebuf);

  if (!nd || !ed)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  RSA *key = bc_rsa_verify_ctx(nd, nl, ed, el);

  if (!key)
    return Nan::ThrowTypeError("Could not allocate context.");

  bool result = bc_rsa_validate(key);

  RSA_free(key);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
