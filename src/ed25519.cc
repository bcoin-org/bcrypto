#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "ed25519/ed25519.h"
#include "ed25519.h"
#include "openssl/crypto.h"

void
BED25519::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "privateKeyConvert", BED25519::PrivateKeyConvert);
  Nan::Export(obj, "scalarTweakAdd", BED25519::ScalarTweakAdd);
  Nan::Export(obj, "scalarTweakMul", BED25519::ScalarTweakMul);
  Nan::Export(obj, "publicKeyCreate", BED25519::PublicKeyCreate);
  Nan::Export(obj, "publicKeyFromScalar", BED25519::PublicKeyFromScalar);
  Nan::Export(obj, "publicKeyConvert", BED25519::PublicKeyConvert);
  Nan::Export(obj, "publicKeyDeconvert", BED25519::PublicKeyDeconvert);
  Nan::Export(obj, "publicKeyVerify", BED25519::PublicKeyVerify);
  Nan::Export(obj, "publicKeyTweakAdd", BED25519::PublicKeyTweakAdd);
  Nan::Export(obj, "publicKeyTweakMul", BED25519::PublicKeyTweakMul);
  Nan::Export(obj, "sign", BED25519::Sign);
  Nan::Export(obj, "signWithScalar", BED25519::SignWithScalar);
  Nan::Export(obj, "signTweakAdd", BED25519::SignTweakAdd);
  Nan::Export(obj, "signTweakMul", BED25519::SignTweakMul);
  Nan::Export(obj, "verify", BED25519::Verify);
  Nan::Export(obj, "derive", BED25519::Derive);
  Nan::Export(obj, "deriveWithScalar", BED25519::DeriveWithScalar);
  Nan::Export(obj, "exchange", BED25519::Exchange);
  Nan::Export(obj, "exchangeWithScalar", BED25519::ExchangeWithScalar);

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

NAN_METHOD(BED25519::ScalarTweakAdd) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed25519.scalarTweakAdd() requires arguments.");

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
    return Nan::ThrowRangeError("Invalid scalar size.");

  if (tweak_len != 32)
    return Nan::ThrowRangeError("Invalid tweak size.");

  bcrypto_ed25519_secret_key out;

  if (bcrypto_ed25519_scalar_tweak_add(out, key, tweak) != 0)
    return Nan::ThrowError("Invalid scalar.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BED25519::ScalarTweakMul) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed25519.scalarTweakMul() requires arguments.");

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
    return Nan::ThrowRangeError("Invalid scalar size.");

  if (tweak_len != 32)
    return Nan::ThrowRangeError("Invalid tweak size.");

  bcrypto_ed25519_secret_key out;

  if (bcrypto_ed25519_scalar_tweak_mul(out, key, tweak) != 0)
    return Nan::ThrowError("Invalid scalar.");

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
  bcrypto_ed25519_publickey(pub, secret);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&pub[0], 32).ToLocalChecked());
}

NAN_METHOD(BED25519::PublicKeyFromScalar) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed25519.publicKeyFromScalar() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t scalar_len = node::Buffer::Length(sbuf);

  if (scalar_len != 32)
    return Nan::ThrowRangeError("Invalid scalar size.");

  bcrypto_ed25519_public_key pub;
  bcrypto_ed25519_publickey_from_scalar(pub, scalar);

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

NAN_METHOD(BED25519::PublicKeyTweakMul) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed25519.publicKeyTweakMul() requires arguments.");

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

  if (bcrypto_ed25519_pubkey_tweak_mul(out, pub, tweak) != 0)
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

  int ph = -1;
  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean or null.");

    ph = (int)Nan::To<bool>(info[2]).FromJust();
  }

  if (info.Length() > 3 && !IsNull(info[3])) {
    v8::Local<v8::Object> cbuf = info[3].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fourth argument must be a buffer or null.");

    if (ph == -1)
      return Nan::ThrowError("Must pass pre-hash flag with context.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

  if (secret_len != 32)
    return Nan::ThrowRangeError("Invalid secret size.");

  bcrypto_ed25519_public_key pub;
  bcrypto_ed25519_publickey(pub, secret);

  bcrypto_ed25519_signature sig;
  bcrypto_ed25519_sign(msg, msg_len, secret, pub, ph, ctx, ctx_len, sig);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&sig[0], 64).ToLocalChecked());
}

NAN_METHOD(BED25519::SignWithScalar) {
  if (info.Length() < 3)
    return Nan::ThrowError("ed25519.signWithScalar() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t scalar_len = node::Buffer::Length(sbuf);

  const uint8_t *prefix = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t prefix_len = node::Buffer::Length(pbuf);

  int ph = -1;
  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean or null.");

    ph = (int)Nan::To<bool>(info[3]).FromJust();
  }

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> cbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fifth argument must be a buffer or null.");

    if (ph == -1)
      return Nan::ThrowError("Must pass pre-hash flag with context.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

  if (scalar_len != 32)
    return Nan::ThrowRangeError("Invalid scalar size.");

  if (prefix_len != 32)
    return Nan::ThrowRangeError("Invalid prefix size.");

  uint8_t expanded[64];

  memcpy(&expanded[0], &scalar[0], 32);
  memcpy(&expanded[32], &prefix[0], 32);

  bcrypto_ed25519_public_key pub;
  bcrypto_ed25519_publickey_from_scalar(pub, scalar);

  bcrypto_ed25519_signature sig;
  bcrypto_ed25519_sign_with_scalar(msg, msg_len, expanded,
                                   pub, ph, ctx, ctx_len, sig);

  OPENSSL_cleanse(&expanded[0], sizeof(expanded));

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&sig[0], 64).ToLocalChecked());
}

NAN_METHOD(BED25519::SignTweakAdd) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed25519.signTweakAdd() requires arguments.");

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

  int ph = -1;
  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean or null.");

    ph = (int)Nan::To<bool>(info[3]).FromJust();
  }

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> cbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fourth argument must be a buffer or null.");

    if (ph == -1)
      return Nan::ThrowError("Must pass pre-hash flag with context.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

  if (secret_len != 32)
    return Nan::ThrowRangeError("Invalid secret size.");

  if (tweak_len != 32)
    return Nan::ThrowRangeError("Invalid tweak size.");

  bcrypto_ed25519_public_key pub;
  bcrypto_ed25519_publickey(pub, secret);

  bcrypto_ed25519_signature sig;

  if (bcrypto_ed25519_sign_tweak_add(msg, msg_len, secret, pub,
                                     tweak, ph, ctx, ctx_len, sig) != 0) {
    return Nan::ThrowError("Could not sign.");
  }

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&sig[0], 64).ToLocalChecked());
}

NAN_METHOD(BED25519::SignTweakMul) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed25519.signTweakMul() requires arguments.");

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

  int ph = -1;
  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean or null.");

    ph = (int)Nan::To<bool>(info[3]).FromJust();
  }

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> cbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fourth argument must be a buffer or null.");

    if (ph == -1)
      return Nan::ThrowError("Must pass pre-hash flag with context.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

  if (secret_len != 32)
    return Nan::ThrowRangeError("Invalid secret size.");

  if (tweak_len != 32)
    return Nan::ThrowRangeError("Invalid tweak size.");

  bcrypto_ed25519_public_key pub;
  bcrypto_ed25519_publickey(pub, secret);

  bcrypto_ed25519_signature sig;

  if (bcrypto_ed25519_sign_tweak_mul(msg, msg_len, secret, pub,
                                     tweak, ph, ctx, ctx_len, sig) != 0) {
    return Nan::ThrowError("Could not sign.");
  }

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

  int ph = -1;
  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean or null.");

    ph = (int)Nan::To<bool>(info[3]).FromJust();
  }

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> cbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fourth argument must be a buffer or null.");

    if (ph == -1)
      return Nan::ThrowError("Must pass pre-hash flag with context.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

  if (sig_len != 64 || pub_len != 32)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = bcrypto_ed25519_sign_open(msg, msg_len, pub,
                                          ph, ctx, ctx_len, sig) == 0;

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

  bcrypto_ed25519_public_key out;

  if (bcrypto_ed25519_derive(out, pub, secret) != 0)
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BED25519::DeriveWithScalar) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed25519.deriveWithScalar() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t scalar_len = node::Buffer::Length(sbuf);

  if (pub_len != 32)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (scalar_len != 32)
    return Nan::ThrowRangeError("Invalid scalar size.");

  bcrypto_ed25519_public_key out;

  if (bcrypto_ed25519_derive_with_scalar(out, pub, scalar) != 0)
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

NAN_METHOD(BED25519::ExchangeWithScalar) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed25519.exchangeWithScalar() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *xpub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t xpub_len = node::Buffer::Length(pbuf);

  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t scalar_len = node::Buffer::Length(sbuf);

  if (xpub_len != 32)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (scalar_len != 32)
    return Nan::ThrowRangeError("Invalid scalar size.");

  bcrypto_curved25519_key out;

  if (bcrypto_ed25519_exchange_with_scalar(out, xpub, scalar) != 0)
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}
