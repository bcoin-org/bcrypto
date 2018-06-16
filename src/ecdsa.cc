#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10

#include "ecdsa/ecdsa.h"
#include "ecdsa.h"

static Nan::Persistent<v8::FunctionTemplate> ecdsa_constructor;

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj);

BECDSA::BECDSA() {}

BECDSA::~BECDSA() {}

void
BECDSA::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BECDSA::New);

  ecdsa_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("ECDSA").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetMethod(tpl, "privateKeyGenerate", BECDSA::PrivateKeyGenerate);
  Nan::SetMethod(tpl, "publicKeyCreate", BECDSA::PublicKeyCreate);
  Nan::SetMethod(tpl, "publicKeyConvert", BECDSA::PublicKeyConvert);
  Nan::SetMethod(tpl, "sign", BECDSA::Sign);
  Nan::SetMethod(tpl, "privateKeyVerify", BECDSA::PrivateKeyVerify);
  Nan::SetMethod(tpl, "verify", BECDSA::Verify);
  Nan::SetMethod(tpl, "publicKeyVerify", BECDSA::PublicKeyVerify);
  Nan::SetMethod(tpl, "ecdh", BECDSA::ECDH);
  Nan::SetMethod(tpl, "privateKeyTweakAdd", BECDSA::PrivateKeyTweakAdd);
  Nan::SetMethod(tpl, "publicKeyTweakAdd", BECDSA::PublicKeyTweakAdd);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(ecdsa_constructor);

  target->Set(Nan::New("ecdsa").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BECDSA::New) {
  return Nan::ThrowError("Could not create ECDSA instance.");
}

NAN_METHOD(BECDSA::PrivateKeyGenerate) {
  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyGenerate() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  uint8_t *priv;
  size_t priv_len;

  if (!bcrypto_ecdsa_generate(name, &priv, &priv_len))
    return Nan::ThrowTypeError("Could not generate key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)&priv[0], priv_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyCreate) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.publicKeyCreate() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  bool compress = true;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean.");

    compress = info[2]->BooleanValue();
  }

  const uint8_t *pd = (uint8_t *)node::Buffer::Data(pbuf);
  size_t pl = node::Buffer::Length(pbuf);

  uint8_t *pub;
  size_t pub_len;

  bool result = bcrypto_ecdsa_create_pub(
    name, pd, pl, compress, &pub, &pub_len);

  if (!result)
    return Nan::ThrowTypeError("Could not create key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)&pub[0], pub_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyConvert) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.publicKeyConvert() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  bool compress = true;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean.");

    compress = info[2]->BooleanValue();
  }

  const uint8_t *pd = (uint8_t *)node::Buffer::Data(pbuf);
  size_t pl = node::Buffer::Length(pbuf);

  uint8_t *pub;
  size_t pub_len;

  bool result = bcrypto_ecdsa_convert_pub(
    name, pd, pl, compress, &pub, &pub_len);

  if (!result)
    return Nan::ThrowTypeError("Could not convert key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)&pub[0], pub_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::Sign) {
  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.sign() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  const uint8_t *pd = (uint8_t *)node::Buffer::Data(pbuf);
  size_t pl = node::Buffer::Length(pbuf);

  if (!pd)
    return Nan::ThrowTypeError("Invalid parameters.");

  uint8_t *r;
  size_t rl;
  uint8_t *s;
  size_t sl;

  bool result = bcrypto_ecdsa_sign(name, md, ml, pd, pl, &r, &rl, &s, &sl);

  if (!result)
    return Nan::ThrowTypeError("Signing failed.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  ret->Set(0, Nan::NewBuffer((char *)&r[0], rl).ToLocalChecked());
  ret->Set(1, Nan::NewBuffer((char *)&s[0], sl).ToLocalChecked());

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(BECDSA::PrivateKeyVerify) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.privateKeyVerify() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *pd = (uint8_t *)node::Buffer::Data(pbuf);
  size_t pl = node::Buffer::Length(pbuf);

  if (!pd)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = bcrypto_ecdsa_verify_priv(name, pd, pl);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::Verify) {
  if (info.Length() < 5)
    return Nan::ThrowError("ecdsa.verify() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> rbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[4].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(rbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  const uint8_t *rd = (uint8_t *)node::Buffer::Data(rbuf);
  size_t rl = node::Buffer::Length(rbuf);

  const uint8_t *sd = (uint8_t *)node::Buffer::Data(sbuf);
  size_t sl = node::Buffer::Length(sbuf);

  const uint8_t *pd = (uint8_t *)node::Buffer::Data(pbuf);
  size_t pl = node::Buffer::Length(pbuf);

  if (!rd || !sd || !pd)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = bcrypto_ecdsa_verify(name, md, ml, rd, rl, sd, sl, pd, pl);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::PublicKeyVerify) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.publicKeyVerify() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *pd = (uint8_t *)node::Buffer::Data(pbuf);
  size_t pl = node::Buffer::Length(pbuf);

  if (!pd)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = bcrypto_ecdsa_verify_pub(name, pd, pl);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::ECDH) {
  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.publicKeyConvert() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  v8::Local<v8::Object> kbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bool compress = true;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    compress = info[3]->BooleanValue();
  }

  const uint8_t *kd = (uint8_t *)node::Buffer::Data(kbuf);
  size_t kl = node::Buffer::Length(kbuf);

  const uint8_t *pd = (uint8_t *)node::Buffer::Data(pbuf);
  size_t pl = node::Buffer::Length(pbuf);

  uint8_t *secret;
  size_t secret_len;

  bool result = bcrypto_ecdsa_ecdh(
    name, kd, kl, pd, pl, compress, &secret, &secret_len);

  if (!result)
    return Nan::ThrowTypeError("Could not perform ECDH.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)&secret[0], secret_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyTweakAdd) {
  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.privateKeyTweakAdd() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pd = (uint8_t *)node::Buffer::Data(pbuf);
  size_t pl = node::Buffer::Length(pbuf);

  const uint8_t *td = (uint8_t *)node::Buffer::Data(tbuf);
  size_t tl = node::Buffer::Length(tbuf);

  uint8_t *priv;
  size_t priv_len;

  bool result = bcrypto_ecdsa_tweak_priv(
    name, pd, pl, td, tl, &priv, &priv_len);

  if (!result)
    return Nan::ThrowTypeError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)&priv[0], priv_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyTweakAdd) {
  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.publicKeyTweakAdd() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bool compress = true;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    compress = info[3]->BooleanValue();
  }

  const uint8_t *pd = (uint8_t *)node::Buffer::Data(pbuf);
  size_t pl = node::Buffer::Length(pbuf);

  const uint8_t *td = (uint8_t *)node::Buffer::Data(tbuf);
  size_t tl = node::Buffer::Length(tbuf);

  uint8_t *pub;
  size_t pub_len;

  bool result = bcrypto_ecdsa_tweak_pub(
    name, pd, pl, td, tl, compress, &pub, &pub_len);

  if (!result)
    return Nan::ThrowTypeError("Could not tweak public key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)&pub[0], pub_len).ToLocalChecked());
}

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;
  return obj->IsNull() || obj->IsUndefined();
}

#endif
