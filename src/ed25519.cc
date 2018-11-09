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
  Nan::Export(obj, "_privateKeyTweakAdd", BED25519::PrivateKeyTweakAdd);
  Nan::Export(obj, "publicKeyCreate", BED25519::PublicKeyCreate);
  Nan::Export(obj, "publicKeyConvert", BED25519::PublicKeyConvert);
  Nan::Export(obj, "publicKeyDeconvert", BED25519::PublicKeyDeconvert);
  Nan::Export(obj, "publicKeyVerify", BED25519::PublicKeyVerify);
  Nan::Export(obj, "publicKeyTweakAdd", BED25519::PublicKeyTweakAdd);
  Nan::Export(obj, "sign", BED25519::Sign);
  Nan::Export(obj, "signTweak", BED25519::SignTweak);
  Nan::Export(obj, "verify", BED25519::Verify);
  Nan::Export(obj, "derive", BED25519::Derive);
  Nan::Export(obj, "exchange", BED25519::Exchange);

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

NAN_METHOD(BED25519::PrivateKeyTweakAdd) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed25519.privateKeyTweakAdd() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t key_len = node::Buffer::Length(kbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  if (key_len != 32)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (tweak_len != 32)
    return Nan::ThrowRangeError("Invalid tweak size.");

  bcrypto_ed25519_secret_key out;

  if (bcrypto_ed25519_privkey_tweak_add(out, key, tweak) != 0)
    return Nan::ThrowError("Invalid public key.");

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

NAN_METHOD(BED25519::PublicKeyDeconvert) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed25519.publicKeyDeconvert() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsBoolean())
    return Nan::ThrowTypeError("Second argument must be a boolean.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != 32)
    return Nan::ThrowRangeError("Invalid public key size.");

  int sign = (int)Nan::To<bool>(info[1]).FromJust();

  bcrypto_ed25519_public_key out;

  if (bcrypto_ed25519_pubkey_deconvert(out, pub, sign) != 0)
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

NAN_METHOD(BED25519::PublicKeyTweakAdd) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed25519.publicKeyTweakAdd() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  if (pub_len != 32)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (tweak_len != 32)
    return Nan::ThrowRangeError("Invalid tweak size.");

  bcrypto_ed25519_public_key out;

  if (bcrypto_ed25519_pubkey_tweak_add(out, pub, tweak) != 0)
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
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

NAN_METHOD(BED25519::SignTweak) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed25519.signTweak() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *secret = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t secret_len = node::Buffer::Length(sbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  if (secret_len != 32)
    return Nan::ThrowRangeError("Invalid secret size.");

  if (tweak_len != 32)
    return Nan::ThrowRangeError("Invalid tweak size.");

  bcrypto_ed25519_public_key pub;
  bcrypto_ed25519_publickey(secret, pub);

  bcrypto_ed25519_signature sig;

  if (bcrypto_ed25519_sign_tweak(msg, msg_len, secret, pub, tweak, sig) != 0)
    return Nan::ThrowError("Could not sign.");

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

NAN_METHOD(BED25519::Derive) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed25519.derive() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  const uint8_t *secret = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t secret_len = node::Buffer::Length(sbuf);

  if (pub_len != 32)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (secret_len != 32)
    return Nan::ThrowRangeError("Invalid secret size.");

  bcrypto_curved25519_key out;

  if (bcrypto_ed25519_derive(out, pub, secret) != 0)
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BED25519::Exchange) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed25519.exchange() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *xpub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t xpub_len = node::Buffer::Length(pbuf);

  const uint8_t *secret = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t secret_len = node::Buffer::Length(sbuf);

  if (xpub_len != 32)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (secret_len != 32)
    return Nan::ThrowRangeError("Invalid secret size.");

  bcrypto_curved25519_key out;

  if (bcrypto_ed25519_exchange(out, xpub, secret) != 0)
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}
