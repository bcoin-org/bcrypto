#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "ed25519/ed25519.h"
#include "ed25519.h"

void
BED25519::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "privateKeyConvert", BED25519::PrivateKeyConvert);
  Nan::Export(obj, "publicKeyCreate", BED25519::PublicKeyCreate);
  Nan::Export(obj, "publicKeyConvert", BED25519::PublicKeyConvert);
  Nan::Export(obj, "publicKeyVerify", BED25519::PublicKeyVerify);
  Nan::Export(obj, "sign", BED25519::Sign);
  Nan::Export(obj, "verify", BED25519::Verify);

  target->Set(Nan::New("ed25519").ToLocalChecked(), obj);
}

NAN_METHOD(BED25519::PrivateKeyConvert) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed25519.privateKeyConvert() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *secret = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t secret_len = node::Buffer::Length(pbuf);

  if (secret_len != 32)
    return Nan::ThrowRangeError("Invalid secret size.");

  bcrypto_ed25519_secret_key out;
  bcrypto_ed25519_privkey_convert(out, secret);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BED25519::PublicKeyCreate) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed25519.publicKeyCreate() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *secret = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t secret_len = node::Buffer::Length(sbuf);

  if (secret_len != 32)
    return Nan::ThrowRangeError("Invalid secret size.");

  bcrypto_ed25519_public_key pub;
  bcrypto_ed25519_publickey(secret, pub);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&pub[0], 32).ToLocalChecked());
}

NAN_METHOD(BED25519::PublicKeyConvert) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed25519.publicKeyConvert() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != 32)
    return Nan::ThrowRangeError("Invalid public key size.");

  bcrypto_curved25519_key out;

  if (bcrypto_ed25519_pubkey_convert(out, pub) != 0)
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BED25519::PublicKeyVerify) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed25519.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != 32)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = bcrypto_ed25519_verify_key(pub) == 0;

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

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *secret = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t secret_len = node::Buffer::Length(sbuf);

  if (secret_len != 32)
    return Nan::ThrowRangeError("Invalid secret size.");

  bcrypto_ed25519_public_key pub;
  bcrypto_ed25519_publickey(secret, pub);

  bcrypto_ed25519_signature sig;
  bcrypto_ed25519_sign(msg, msg_len, secret, pub, sig);

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

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (sig_len != 64 || pub_len != 32)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = bcrypto_ed25519_sign_open(msg, msg_len, pub, sig) == 0;

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
