#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10

#include "dsa/dsa.h"
#include "dsa.h"
#include "dsa_async.h"

static Nan::Persistent<v8::FunctionTemplate> dsa_constructor;

BDSA::BDSA() {}

BDSA::~BDSA() {}

void
BDSA::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BDSA::New);

  dsa_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("DSA").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetMethod(tpl, "paramsGenerate", BDSA::ParamsGenerate);
  Nan::SetMethod(tpl, "paramsGenerateAsync", BDSA::ParamsGenerateAsync);
  Nan::SetMethod(tpl, "privateKeyCreate", BDSA::PrivateKeyCreate);
  Nan::SetMethod(tpl, "computeY", BDSA::ComputeY);
  Nan::SetMethod(tpl, "sign", BDSA::Sign);
  Nan::SetMethod(tpl, "verify", BDSA::Verify);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(dsa_constructor);

  target->Set(Nan::New("dsa").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BDSA::New) {
  return Nan::ThrowError("Could not create DSA instance.");
}

NAN_METHOD(BDSA::ParamsGenerate) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.paramsGenerate() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  uint32_t bits = info[0]->Uint32Value();

  bcrypto_dsa_key_t *k = bcrypto_dsa_generate_params((int)bits);

  if (!k)
    return Nan::ThrowTypeError("Could not generate key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  ret->Set(0, Nan::CopyBuffer((char *)&k->pd[0], k->pl).ToLocalChecked());
  ret->Set(1, Nan::CopyBuffer((char *)&k->qd[0], k->ql).ToLocalChecked());
  ret->Set(2, Nan::CopyBuffer((char *)&k->gd[0], k->gl).ToLocalChecked());

  bcrypto_dsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BDSA::ParamsGenerateAsync) {
  if (info.Length() < 2)
    return Nan::ThrowError("dsa.paramsGenerateAsync() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsFunction())
    return Nan::ThrowTypeError("Second argument must be a function.");

  uint32_t bits = info[0]->Uint32Value();

  v8::Local<v8::Function> callback = info[1].As<v8::Function>();

  BDSAWorker *worker = new BDSAWorker(
    (int)bits,
    new Nan::Callback(callback)
  );

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(BDSA::PrivateKeyCreate) {
  if (info.Length() < 3)
    return Nan::ThrowError("dsa.privateKeyCreate() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t params;
  bcrypto_dsa_key_init(&params);

  params.pd = (uint8_t *)node::Buffer::Data(pbuf);
  params.pl = node::Buffer::Length(pbuf);

  params.qd = (uint8_t *)node::Buffer::Data(qbuf);
  params.ql = node::Buffer::Length(qbuf);

  params.gd = (uint8_t *)node::Buffer::Data(gbuf);
  params.gl = node::Buffer::Length(gbuf);

  bcrypto_dsa_key_t *k = bcrypto_dsa_generate(&params);

  if (!k)
    return Nan::ThrowTypeError("Could not generate key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  ret->Set(0, Nan::CopyBuffer((char *)&k->pd[0], k->pl).ToLocalChecked());
  ret->Set(1, Nan::CopyBuffer((char *)&k->qd[0], k->ql).ToLocalChecked());
  ret->Set(2, Nan::CopyBuffer((char *)&k->gd[0], k->gl).ToLocalChecked());
  ret->Set(3, Nan::CopyBuffer((char *)&k->yd[0], k->yl).ToLocalChecked());
  ret->Set(4, Nan::CopyBuffer((char *)&k->xd[0], k->xl).ToLocalChecked());

  bcrypto_dsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BDSA::ComputeY) {
  if (info.Length() < 3)
    return Nan::ThrowError("dsa.computeY() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> xbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(xbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t priv;
  bcrypto_dsa_key_init(&priv);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.gd = (uint8_t *)node::Buffer::Data(gbuf);
  priv.gl = node::Buffer::Length(gbuf);

  priv.xd = (uint8_t *)node::Buffer::Data(xbuf);
  priv.xl = node::Buffer::Length(xbuf);

  uint8_t *y;
  size_t y_len;

  if (!bcrypto_dsa_create_pub(&priv, &y, &y_len))
    return Nan::ThrowTypeError("Could not create public key.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)&y[0], y_len).ToLocalChecked());
}

NAN_METHOD(BDSA::Sign) {
  if (info.Length() < 6)
    return Nan::ThrowError("dsa.sign() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> xbuf = info[5].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)
      || !node::Buffer::HasInstance(xbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t priv;
  bcrypto_dsa_key_init(&priv);

  const uint8_t *md = (uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.gd = (uint8_t *)node::Buffer::Data(gbuf);
  priv.gl = node::Buffer::Length(gbuf);

  priv.yd = (uint8_t *)node::Buffer::Data(ybuf);
  priv.yl = node::Buffer::Length(ybuf);

  priv.xd = (uint8_t *)node::Buffer::Data(xbuf);
  priv.xl = node::Buffer::Length(xbuf);

  uint8_t *r;
  size_t rl;
  uint8_t *s;
  size_t sl;

  if (!bcrypto_dsa_sign(md, ml, &priv, &r, &rl, &s, &sl))
    return Nan::ThrowTypeError("Could not sign message.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  ret->Set(0, Nan::NewBuffer((char *)&r[0], rl).ToLocalChecked());
  ret->Set(1, Nan::NewBuffer((char *)&s[0], sl).ToLocalChecked());

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(BDSA::Verify) {
  if (info.Length() < 7)
    return Nan::ThrowError("dsa.verify() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> rbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[6].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(rbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  const uint8_t *rd = (uint8_t *)node::Buffer::Data(rbuf);
  size_t rl = node::Buffer::Length(rbuf);

  const uint8_t *sd = (uint8_t *)node::Buffer::Data(sbuf);
  size_t sl = node::Buffer::Length(sbuf);

  bcrypto_dsa_key_t pub;
  bcrypto_dsa_key_init(&pub);

  pub.pd = (uint8_t *)node::Buffer::Data(pbuf);
  pub.pl = node::Buffer::Length(pbuf);

  pub.qd = (uint8_t *)node::Buffer::Data(qbuf);
  pub.ql = node::Buffer::Length(qbuf);

  pub.gd = (uint8_t *)node::Buffer::Data(gbuf);
  pub.gl = node::Buffer::Length(gbuf);

  pub.yd = (uint8_t *)node::Buffer::Data(ybuf);
  pub.yl = node::Buffer::Length(ybuf);

  bool result = bcrypto_dsa_verify(md, ml, rd, rl, sd, sl, &pub);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
#endif
