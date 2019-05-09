#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "ecdsa/ecdsa.h"
#include "ecdsa.h"

#ifdef BCRYPTO_HAS_ECDSA

static Nan::Persistent<v8::FunctionTemplate> ecdsa_constructor;

BECDSA::BECDSA() {
  memset(&ctx, 0x00, sizeof(bcrypto_ecdsa_t));
}

BECDSA::~BECDSA() {
  bcrypto_ecdsa_uninit(&ctx);
}

void
BECDSA::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BECDSA::New);

  ecdsa_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("ECDSA").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "_size", BECDSA::Size);
  Nan::SetPrototypeMethod(tpl, "_bits", BECDSA::Bits);
  Nan::SetPrototypeMethod(tpl, "privateKeyGenerate", BECDSA::PrivateKeyGenerate);
  Nan::SetPrototypeMethod(tpl, "privateKeyVerify", BECDSA::PrivateKeyVerify);
  Nan::SetPrototypeMethod(tpl, "privateKeyExport", BECDSA::PrivateKeyExport);
  Nan::SetPrototypeMethod(tpl, "privateKeyImport", BECDSA::PrivateKeyImport);
  Nan::SetPrototypeMethod(tpl, "privateKeyExportPKCS8", BECDSA::PrivateKeyExportPKCS8);
  Nan::SetPrototypeMethod(tpl, "privateKeyImportPKCS8", BECDSA::PrivateKeyImportPKCS8);
  Nan::SetPrototypeMethod(tpl, "privateKeyTweakAdd", BECDSA::PrivateKeyTweakAdd);
  Nan::SetPrototypeMethod(tpl, "privateKeyTweakMul", BECDSA::PrivateKeyTweakMul);
  Nan::SetPrototypeMethod(tpl, "privateKeyMod", BECDSA::PrivateKeyMod);
  Nan::SetPrototypeMethod(tpl, "privateKeyNegate", BECDSA::PrivateKeyNegate);
  Nan::SetPrototypeMethod(tpl, "privateKeyInverse", BECDSA::PrivateKeyInverse);
  Nan::SetPrototypeMethod(tpl, "publicKeyCreate", BECDSA::PublicKeyCreate);
  Nan::SetPrototypeMethod(tpl, "publicKeyConvert", BECDSA::PublicKeyConvert);
  Nan::SetPrototypeMethod(tpl, "publicKeyVerify", BECDSA::PublicKeyVerify);
  Nan::SetPrototypeMethod(tpl, "publicKeyExportSPKI", BECDSA::PublicKeyExportSPKI);
  Nan::SetPrototypeMethod(tpl, "publicKeyImportSPKI", BECDSA::PublicKeyImportSPKI);
  Nan::SetPrototypeMethod(tpl, "publicKeyTweakAdd", BECDSA::PublicKeyTweakAdd);
  Nan::SetPrototypeMethod(tpl, "publicKeyTweakMul", BECDSA::PublicKeyTweakMul);
  Nan::SetPrototypeMethod(tpl, "publicKeyAdd", BECDSA::PublicKeyAdd);
  Nan::SetPrototypeMethod(tpl, "publicKeyNegate", BECDSA::PublicKeyNegate);
  Nan::SetPrototypeMethod(tpl, "signatureNormalize", BECDSA::SignatureNormalize);
  Nan::SetPrototypeMethod(tpl, "signatureExport", BECDSA::SignatureExport);
  Nan::SetPrototypeMethod(tpl, "signatureImport", BECDSA::SignatureImport);
  Nan::SetPrototypeMethod(tpl, "isLowS", BECDSA::IsLowS);
  Nan::SetPrototypeMethod(tpl, "isLowDER", BECDSA::IsLowDER);
  Nan::SetPrototypeMethod(tpl, "sign", BECDSA::Sign);
  Nan::SetPrototypeMethod(tpl, "signDER", BECDSA::SignDER);
  Nan::SetPrototypeMethod(tpl, "signRecoverable", BECDSA::SignRecoverable);
  Nan::SetPrototypeMethod(tpl, "signRecoverableDER", BECDSA::SignRecoverableDER);
  Nan::SetPrototypeMethod(tpl, "verify", BECDSA::Verify);
  Nan::SetPrototypeMethod(tpl, "verifyDER", BECDSA::VerifyDER);
  Nan::SetPrototypeMethod(tpl, "recover", BECDSA::Recover);
  Nan::SetPrototypeMethod(tpl, "recoverDER", BECDSA::RecoverDER);
  Nan::SetPrototypeMethod(tpl, "derive", BECDSA::Derive);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(ecdsa_constructor);

  Nan::Set(target, Nan::New("ECDSA").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BECDSA::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create ECDSA instance.");

  if (info.Length() < 1)
    return Nan::ThrowError("ECDSA() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  BECDSA *ec = new BECDSA();

  if (!bcrypto_ecdsa_init(&ec->ctx, name))
    return Nan::ThrowTypeError("Curve not available.");

  ec->Wrap(info.This());

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BECDSA::Size) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());
  return info.GetReturnValue().Set(Nan::New<v8::Number>(ec->ctx.size));
}

NAN_METHOD(BECDSA::Bits) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());
  return info.GetReturnValue().Set(Nan::New<v8::Number>(ec->ctx.bits));
}

NAN_METHOD(BECDSA::PrivateKeyGenerate) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  uint8_t priv[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];

  if (!bcrypto_ecdsa_privkey_generate(&ec->ctx, priv))
    return Nan::ThrowError("Could not generate key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)priv, ec->ctx.scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyVerify) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != ec->ctx.scalar_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = bcrypto_ecdsa_privkey_verify(&ec->ctx, priv);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::PrivateKeyExport) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyExport() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  int compress = 1;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[1]).FromJust();
  }

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != ec->ctx.scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t *out;
  size_t out_len;

  if (!bcrypto_ecdsa_privkey_export(&ec->ctx, &out, &out_len, priv, compress))
    return Nan::ThrowError("Could not export key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyImport) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyImport() requires arguments.");

  v8::Local<v8::Object> rbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *raw = (const uint8_t *)node::Buffer::Data(rbuf);
  size_t raw_len = node::Buffer::Length(rbuf);

  uint8_t out[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];

  if (!bcrypto_ecdsa_privkey_import(&ec->ctx, out, raw, raw_len))
    return Nan::ThrowError("Could not import key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->ctx.scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyExportPKCS8) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyExportPKCS8() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  int compress = 1;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[1]).FromJust();
  }

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != ec->ctx.scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t *out;
  size_t out_len;

  int result = bcrypto_ecdsa_privkey_export_pkcs8(&ec->ctx, &out,
                                                  &out_len, priv,
                                                  compress);

  if (!result)
    return Nan::ThrowError("Could not export key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyImportPKCS8) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyImportPKCS8() requires arguments.");

  v8::Local<v8::Object> rbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *raw = (const uint8_t *)node::Buffer::Data(rbuf);
  size_t raw_len = node::Buffer::Length(rbuf);

  uint8_t out[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];

  if (!bcrypto_ecdsa_privkey_import_pkcs8(&ec->ctx, out, raw, raw_len))
    return Nan::ThrowError("Could not import key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->ctx.scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyTweakAdd) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.privateKeyTweakAdd() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  if (priv_len != ec->ctx.scalar_size || tweak_len != ec->ctx.scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];

  if (!bcrypto_ecdsa_privkey_tweak_add(&ec->ctx, out, priv, tweak))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->ctx.scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyTweakMul) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.privateKeyTweakMul() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  if (priv_len != ec->ctx.scalar_size || tweak_len != ec->ctx.scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];

  if (!bcrypto_ecdsa_privkey_tweak_mul(&ec->ctx, out, priv, tweak))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->ctx.scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyMod) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyMod() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  uint8_t out[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];

  if (!bcrypto_ecdsa_privkey_mod(&ec->ctx, out, priv, priv_len))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->ctx.scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyNegate) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyNegate() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != ec->ctx.scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];

  if (!bcrypto_ecdsa_privkey_negate(&ec->ctx, out, priv))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->ctx.scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyInverse) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyInverse() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != ec->ctx.scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];

  if (!bcrypto_ecdsa_privkey_inverse(&ec->ctx, out, priv))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->ctx.scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyCreate) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.publicKeyCreate() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  int compress = 1;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[1]).FromJust();
  }

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != ec->ctx.scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  bcrypto_ecdsa_pubkey_t pubkey;
  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_pubkey_create(&ec->ctx, &pubkey, priv))
    return Nan::ThrowError("Could not create key.");

  bcrypto_ecdsa_pubkey_encode(&ec->ctx, out, &out_len, &pubkey, compress);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyConvert) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.publicKeyConvert() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  int compress = 1;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[1]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  bcrypto_ecdsa_pubkey_t pubkey;
  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_pubkey_decode(&ec->ctx, &pubkey, pub, pub_len))
    return Nan::ThrowError("Invalid public key.");

  bcrypto_ecdsa_pubkey_encode(&ec->ctx, out, &out_len, &pubkey, compress);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyVerify) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  bcrypto_ecdsa_pubkey_t pubkey;

  if (!bcrypto_ecdsa_pubkey_decode(&ec->ctx, &pubkey, pub, pub_len))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(true));
}

NAN_METHOD(BECDSA::PublicKeyExportSPKI) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyExportPKCS8() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  int compress = 1;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[1]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  bcrypto_ecdsa_pubkey_t pubkey;

  if (!bcrypto_ecdsa_pubkey_decode(&ec->ctx, &pubkey, pub, pub_len))
    return Nan::ThrowError("Invalid public key.");

  uint8_t *out;
  size_t out_len;

  int result = bcrypto_ecdsa_pubkey_export_spki(&ec->ctx, &out,
                                                &out_len, &pubkey,
                                                compress);

  if (!result)
    return Nan::ThrowError("Could not export key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyImportSPKI) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyImportPKCS8() requires arguments.");

  v8::Local<v8::Object> rbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  int compress = 1;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[1]).FromJust();
  }

  const uint8_t *raw = (const uint8_t *)node::Buffer::Data(rbuf);
  size_t raw_len = node::Buffer::Length(rbuf);

  bcrypto_ecdsa_pubkey_t pubkey;
  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_pubkey_import_spki(&ec->ctx, &pubkey, raw, raw_len))
    return Nan::ThrowError("Could not import key.");

  bcrypto_ecdsa_pubkey_encode(&ec->ctx, out, &out_len, &pubkey, compress);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyTweakAdd) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.publicKeyTweakAdd() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int compress = 1;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[2]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  if (tweak_len != ec->ctx.scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  bcrypto_ecdsa_pubkey_t pubkey;
  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_pubkey_decode(&ec->ctx, &pubkey, pub, pub_len))
    return Nan::ThrowError("Invalid public key.");

  if (!bcrypto_ecdsa_pubkey_tweak_add(&ec->ctx, &pubkey, &pubkey, tweak))
    return Nan::ThrowError("Could not tweak public key.");

  bcrypto_ecdsa_pubkey_encode(&ec->ctx, out, &out_len, &pubkey, compress);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyTweakMul) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.publicKeyTweakMul() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int compress = 1;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[2]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  if (tweak_len != ec->ctx.scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  bcrypto_ecdsa_pubkey_t pubkey;
  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_pubkey_decode(&ec->ctx, &pubkey, pub, pub_len))
    return Nan::ThrowError("Invalid public key.");

  if (!bcrypto_ecdsa_pubkey_tweak_mul(&ec->ctx, &pubkey, &pubkey, tweak))
    return Nan::ThrowError("Could not tweak public key.");

  bcrypto_ecdsa_pubkey_encode(&ec->ctx, out, &out_len, &pubkey, compress);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyAdd) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.publicKeyAdd() requires arguments.");

  v8::Local<v8::Object> p1buf = info[0].As<v8::Object>();
  v8::Local<v8::Object> p2buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(p1buf)
      || !node::Buffer::HasInstance(p2buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int compress = 1;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[2]).FromJust();
  }

  const uint8_t *pub1 = (const uint8_t *)node::Buffer::Data(p1buf);
  size_t pub1_len = node::Buffer::Length(p1buf);

  const uint8_t *pub2 = (const uint8_t *)node::Buffer::Data(p2buf);
  size_t pub2_len = node::Buffer::Length(p2buf);

  bcrypto_ecdsa_pubkey_t pubkey1;
  bcrypto_ecdsa_pubkey_t pubkey2;
  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_pubkey_decode(&ec->ctx, &pubkey1, pub1, pub1_len))
    return Nan::ThrowError("Invalid public key.");

  if (!bcrypto_ecdsa_pubkey_decode(&ec->ctx, &pubkey2, pub2, pub2_len))
    return Nan::ThrowError("Invalid public key.");

  if (!bcrypto_ecdsa_pubkey_add(&ec->ctx, &pubkey1, &pubkey1, &pubkey2))
    return Nan::ThrowError("Could not tweak public key.");

  bcrypto_ecdsa_pubkey_encode(&ec->ctx, out, &out_len, &pubkey1, compress);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyNegate) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.publicKeyNegate() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  int compress = 1;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[1]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  bcrypto_ecdsa_pubkey_t pubkey;
  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_pubkey_decode(&ec->ctx, &pubkey, pub, pub_len))
    return Nan::ThrowError("Invalid public key.");

  if (!bcrypto_ecdsa_pubkey_negate(&ec->ctx, &pubkey, &pubkey))
    return Nan::ThrowError("Could not tweak public key.");

  bcrypto_ecdsa_pubkey_encode(&ec->ctx, out, &out_len, &pubkey, compress);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignatureNormalize) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.signatureNormalize() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  if (sig_len != ec->ctx.sig_size)
    return Nan::ThrowRangeError("Invalid length.");

  bcrypto_ecdsa_sig_t sign;
  uint8_t out[BCRYPTO_ECDSA_MAX_SIG_SIZE];

  if (!bcrypto_ecdsa_sig_decode(&ec->ctx, &sign, sig))
    return Nan::ThrowError("Invalid signature.");

  bcrypto_ecdsa_sig_normalize(&ec->ctx, &sign, &sign);
  bcrypto_ecdsa_sig_encode(&ec->ctx, out, &sign);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->ctx.sig_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignatureExport) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.signatureExport() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  if (sig_len != ec->ctx.sig_size)
    return Nan::ThrowRangeError("Invalid length.");

  bcrypto_ecdsa_sig_t sign;
  uint8_t out[BCRYPTO_ECDSA_MAX_DER_SIZE];
  size_t out_len = BCRYPTO_ECDSA_MAX_DER_SIZE;

  if (!bcrypto_ecdsa_sig_decode(&ec->ctx, &sign, sig))
    return Nan::ThrowError("Invalid signature.");

  if (!bcrypto_ecdsa_sig_encode_der(&ec->ctx, out, &out_len, &sign))
    return Nan::ThrowError("Serialization failed.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignatureImport) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.signatureImport() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  if (sig_len == 0)
    return Nan::ThrowRangeError("Invalid length.");

  bcrypto_ecdsa_sig_t sign;
  uint8_t out[BCRYPTO_ECDSA_MAX_SIG_SIZE];

  if (!bcrypto_ecdsa_sig_decode_der(&ec->ctx, &sign, sig, sig_len))
    return Nan::ThrowError("Invalid signature.");

  bcrypto_ecdsa_sig_encode(&ec->ctx, out, &sign);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->ctx.sig_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::IsLowS) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.isLowS() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  if (sig_len != ec->ctx.sig_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bcrypto_ecdsa_sig_t sign;

  if (!bcrypto_ecdsa_sig_decode(&ec->ctx, &sign, sig))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = bcrypto_ecdsa_sig_is_low_s(&ec->ctx, &sign);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::IsLowDER) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.isLowDER() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  if (sig_len == 0)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bcrypto_ecdsa_sig_t sign;

  if (!bcrypto_ecdsa_sig_decode_der(&ec->ctx, &sign, sig, sig_len))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = bcrypto_ecdsa_sig_is_low_s(&ec->ctx, &sign);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::Sign) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.sign() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != ec->ctx.scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  bcrypto_ecdsa_sig_t sign;
  uint8_t out[BCRYPTO_ECDSA_MAX_SIG_SIZE];

  if (!bcrypto_ecdsa_sign(&ec->ctx, &sign, msg, msg_len, priv))
    return Nan::ThrowError("Could not sign.");

  bcrypto_ecdsa_sig_encode(&ec->ctx, out, &sign);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->ctx.sig_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignDER) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.signDER() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != ec->ctx.scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  bcrypto_ecdsa_sig_t sign;
  uint8_t out[BCRYPTO_ECDSA_MAX_DER_SIZE];
  size_t out_len = BCRYPTO_ECDSA_MAX_DER_SIZE;

  if (!bcrypto_ecdsa_sign(&ec->ctx, &sign, msg, msg_len, priv))
    return Nan::ThrowError("Could not sign.");

  if (!bcrypto_ecdsa_sig_encode_der(&ec->ctx, out, &out_len, &sign))
    return Nan::ThrowError("Could not sign.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignRecoverable) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.signRecoverable() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != ec->ctx.scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  bcrypto_ecdsa_sig_t sign;
  uint8_t out[BCRYPTO_ECDSA_MAX_SIG_SIZE];

  if (!bcrypto_ecdsa_sign_recoverable(&ec->ctx, &sign, msg, msg_len, priv))
    return Nan::ThrowError("Could not sign.");

  bcrypto_ecdsa_sig_encode(&ec->ctx, out, &sign);

  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Set(obj, Nan::New<v8::String>("signature").ToLocalChecked(),
    Nan::CopyBuffer((char *)out, ec->ctx.sig_size).ToLocalChecked());
  Nan::Set(obj, Nan::New<v8::String>("recovery").ToLocalChecked(),
    Nan::New<v8::Number>(sign.param));

  return info.GetReturnValue().Set(obj);
}

NAN_METHOD(BECDSA::SignRecoverableDER) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.signRecoverableDER() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != ec->ctx.scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  bcrypto_ecdsa_sig_t sign;
  uint8_t out[BCRYPTO_ECDSA_MAX_DER_SIZE];
  size_t out_len = BCRYPTO_ECDSA_MAX_DER_SIZE;

  if (!bcrypto_ecdsa_sign_recoverable(&ec->ctx, &sign, msg, msg_len, priv))
    return Nan::ThrowError("Could not sign.");

  if (!bcrypto_ecdsa_sig_encode_der(&ec->ctx, out, &out_len, &sign))
    return Nan::ThrowError("Could not sign.");

  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Set(obj, Nan::New<v8::String>("signature").ToLocalChecked(),
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
  Nan::Set(obj, Nan::New<v8::String>("recovery").ToLocalChecked(),
    Nan::New<v8::Number>(sign.param));

  return info.GetReturnValue().Set(obj);
}

NAN_METHOD(BECDSA::Verify) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.verify() requires arguments.");

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

  if (sig_len != ec->ctx.sig_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bcrypto_ecdsa_sig_t sign;
  bcrypto_ecdsa_pubkey_t pubkey;

  if (!bcrypto_ecdsa_sig_decode(&ec->ctx, &sign, sig))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  if (!bcrypto_ecdsa_pubkey_decode(&ec->ctx, &pubkey, pub, pub_len))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = bcrypto_ecdsa_verify(&ec->ctx, msg, msg_len, &sign, &pubkey);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::VerifyDER) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.verify() requires arguments.");

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

  if (sig_len == 0)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bcrypto_ecdsa_sig_t sign;
  bcrypto_ecdsa_pubkey_t pubkey;

  if (!bcrypto_ecdsa_sig_decode_der(&ec->ctx, &sign, sig, sig_len))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  if (!bcrypto_ecdsa_pubkey_decode(&ec->ctx, &pubkey, pub, pub_len))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = bcrypto_ecdsa_verify(&ec->ctx, msg, msg_len, &sign, &pubkey);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::Recover) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.recover() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  int param = (int)Nan::To<uint32_t>(info[2]).FromJust();
  int compress = 1;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[3]).FromJust();
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  if (sig_len != ec->ctx.sig_size)
    return info.GetReturnValue().Set(Nan::Null());

  bcrypto_ecdsa_sig_t sign;

  if (!bcrypto_ecdsa_sig_decode(&ec->ctx, &sign, sig))
    return info.GetReturnValue().Set(Nan::Null());

  bcrypto_ecdsa_pubkey_t pubkey;

  if (!bcrypto_ecdsa_recover(&ec->ctx, &pubkey, msg, msg_len, &sign, param))
    return info.GetReturnValue().Set(Nan::Null());

  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  bcrypto_ecdsa_pubkey_encode(&ec->ctx, out, &out_len, &pubkey, compress);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::RecoverDER) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.recover() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  int param = (int)Nan::To<uint32_t>(info[2]).FromJust();
  int compress = 1;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[3]).FromJust();
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  if (sig_len == 0)
    return info.GetReturnValue().Set(Nan::Null());

  bcrypto_ecdsa_sig_t sign;

  if (!bcrypto_ecdsa_sig_decode_der(&ec->ctx, &sign, sig, sig_len))
    return info.GetReturnValue().Set(Nan::Null());

  bcrypto_ecdsa_pubkey_t pubkey;

  if (!bcrypto_ecdsa_recover(&ec->ctx, &pubkey, msg, msg_len, &sign, param))
    return info.GetReturnValue().Set(Nan::Null());

  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  bcrypto_ecdsa_pubkey_encode(&ec->ctx, out, &out_len, &pubkey, compress);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::Derive) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.derive() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int compress = 1;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[2]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t pub_len = node::Buffer::Length(kbuf);

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != ec->ctx.scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  bcrypto_ecdsa_pubkey_t pubkey;
  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_pubkey_decode(&ec->ctx, &pubkey, pub, pub_len))
    return Nan::ThrowError("Invalid public key.");

  if (!bcrypto_ecdsa_derive(&ec->ctx, &pubkey, &pubkey, priv))
    return Nan::ThrowError("Could not perform ECDH.");

  bcrypto_ecdsa_pubkey_encode(&ec->ctx, out, &out_len, &pubkey, compress);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

#endif
