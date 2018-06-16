#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10

#include "rsa/rsa.h"
#include "rsa.h"
#include "rsa_async.h"

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
  Nan::SetMethod(tpl, "privateKeyGenerateAsync", BRSA::PrivateKeyGenerateAsync);
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

  bcrypto_rsa_key_t *k = bcrypto_rsa_generate((int)bits, 0);

  if (!k)
    return Nan::ThrowTypeError("Could not generate key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  ret->Set(0, Nan::CopyBuffer((char *)&k->nd[0], k->nl).ToLocalChecked());
  ret->Set(1, Nan::CopyBuffer((char *)&k->ed[0], k->el).ToLocalChecked());
  ret->Set(2, Nan::CopyBuffer((char *)&k->dd[0], k->dl).ToLocalChecked());
  ret->Set(3, Nan::CopyBuffer((char *)&k->pd[0], k->pl).ToLocalChecked());
  ret->Set(4, Nan::CopyBuffer((char *)&k->qd[0], k->ql).ToLocalChecked());
  ret->Set(5, Nan::CopyBuffer((char *)&k->dpd[0], k->dpl).ToLocalChecked());
  ret->Set(6, Nan::CopyBuffer((char *)&k->dqd[0], k->dql).ToLocalChecked());
  ret->Set(7, Nan::CopyBuffer((char *)&k->qid[0], k->qil).ToLocalChecked());

  bcrypto_rsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BRSA::PrivateKeyGenerateAsync) {
  if (info.Length() < 2)
    return Nan::ThrowError("rsa.privateKeyGenerateAsync() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsFunction())
    return Nan::ThrowTypeError("Second argument must be a function.");

  uint32_t bits = info[0]->Uint32Value();

  v8::Local<v8::Function> callback = info[1].As<v8::Function>();

  BRSAWorker *worker = new BRSAWorker(
    (int)bits,
    0,
    new Nan::Callback(callback)
  );

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(BRSA::Sign) {
  if (info.Length() < 10)
    return Nan::ThrowError("rsa.sign() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String alg_(info[0]);
  const char *alg = (const char *)*alg_;

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

  bcrypto_rsa_key_t priv;
  bcrypto_rsa_key_init(&priv);

  const uint8_t *md = (uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  priv.nd = (uint8_t *)node::Buffer::Data(nbuf);
  priv.nl = node::Buffer::Length(nbuf);

  priv.ed = (uint8_t *)node::Buffer::Data(ebuf);
  priv.el = node::Buffer::Length(ebuf);

  priv.dd = (uint8_t *)node::Buffer::Data(dbuf);
  priv.dl = node::Buffer::Length(dbuf);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.dpd = (uint8_t *)node::Buffer::Data(dpbuf);
  priv.dpl = node::Buffer::Length(dpbuf);

  priv.dqd = (uint8_t *)node::Buffer::Data(dqbuf);
  priv.dql = node::Buffer::Length(dqbuf);

  priv.qid = (uint8_t *)node::Buffer::Data(qibuf);
  priv.qil = node::Buffer::Length(qibuf);

  uint8_t *sig;
  size_t sig_len;

  if (!bcrypto_rsa_sign(alg, md, ml, &priv, &sig, &sig_len))
    return Nan::ThrowTypeError("Could not sign message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)&sig[0], sig_len).ToLocalChecked());
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

  bcrypto_rsa_key_t priv;
  bcrypto_rsa_key_init(&priv);

  priv.nd = (uint8_t *)node::Buffer::Data(nbuf);
  priv.nl = node::Buffer::Length(nbuf);

  priv.ed = (uint8_t *)node::Buffer::Data(ebuf);
  priv.el = node::Buffer::Length(ebuf);

  priv.dd = (uint8_t *)node::Buffer::Data(dbuf);
  priv.dl = node::Buffer::Length(dbuf);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.dpd = (uint8_t *)node::Buffer::Data(dpbuf);
  priv.dpl = node::Buffer::Length(dpbuf);

  priv.dqd = (uint8_t *)node::Buffer::Data(dqbuf);
  priv.dql = node::Buffer::Length(dqbuf);

  priv.qid = (uint8_t *)node::Buffer::Data(qibuf);
  priv.qil = node::Buffer::Length(qibuf);

  bool result = bcrypto_rsa_verify_priv(&priv);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BRSA::Verify) {
  if (info.Length() < 5)
    return Nan::ThrowError("rsa.verify() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String alg_(info[0]);
  const char *alg = (const char *)*alg_;

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

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  bool result = bcrypto_rsa_verify(alg, md, ml, sd, sl, &pub);

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

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  bool result = bcrypto_rsa_verify_pub(&pub);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
#endif
