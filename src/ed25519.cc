#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10

#include "ed25519/ed25519.h"
#include "ed25519.h"

static Nan::Persistent<v8::FunctionTemplate> ed25519_constructor;

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj);

BED25519::BED25519() {}

BED25519::~BED25519() {}

void
BED25519::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BED25519::New);

  ed25519_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("ED25519").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetMethod(tpl, "publicKeyCreate", BED25519::PublicKeyCreate);
  Nan::SetMethod(tpl, "publicKeyVerify", BED25519::PublicKeyVerify);
  Nan::SetMethod(tpl, "sign", BED25519::Sign);
  Nan::SetMethod(tpl, "verify", BED25519::Verify);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(ed25519_constructor);

  target->Set(Nan::New("ed25519").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BED25519::New) {
  return Nan::ThrowError("Could not create ED25519 instance.");
}

NAN_METHOD(BED25519::PublicKeyCreate) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed25519.publicKeyCreate() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Argument must be a buffer.");

  const uint8_t *secret = (uint8_t *)node::Buffer::Data(sbuf);
  size_t secret_len = node::Buffer::Length(sbuf);

  if (secret_len != 32)
    return Nan::ThrowError("Invalid private key.");

  ed25519_public_key pub;
  ed25519_publickey(secret, pub);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&pub[0], 32).ToLocalChecked());
}

NAN_METHOD(BED25519::PublicKeyVerify) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed25519.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Argument must be a buffer.");

  const uint8_t *pub = (uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != 32)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = ed25519_verify_key(pub) == 0;

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BED25519::Sign) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed25519.sign() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *secret = (uint8_t *)node::Buffer::Data(sbuf);
  size_t secret_len = node::Buffer::Length(sbuf);

  if (secret_len != 32)
    return Nan::ThrowTypeError("Invalid parameters.");

  ed25519_public_key pub;
  ed25519_publickey(secret, pub);

  ed25519_signature sig;
  ed25519_sign(msg, msg_len, secret, pub, sig);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&sig[0], 64).ToLocalChecked());
}

NAN_METHOD(BED25519::Verify) {
  if (info.Length() < 3)
    return Nan::ThrowError("ed25519.verify() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *sig = (uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  const uint8_t *pub = (uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (sig_len != 64 || pub_len != 32)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = ed25519_sign_open(msg, msg_len, pub, sig) == 0;

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;
  return obj->IsNull() || obj->IsUndefined();
}

#endif
