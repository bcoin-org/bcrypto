#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "ecdsa/ecdsa.h"
#include "ecdsa.h"

void
BECDSA::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "_size", BECDSA::Size);
  Nan::Export(obj, "_bits", BECDSA::Bits);
  Nan::Export(obj, "privateKeyGenerate", BECDSA::PrivateKeyGenerate);
  Nan::Export(obj, "privateKeyVerify", BECDSA::PrivateKeyVerify);
  Nan::Export(obj, "privateKeyExport", BECDSA::PrivateKeyExport);
  Nan::Export(obj, "privateKeyImport", BECDSA::PrivateKeyImport);
  Nan::Export(obj, "privateKeyExportPKCS8", BECDSA::PrivateKeyExportPKCS8);
  Nan::Export(obj, "privateKeyImportPKCS8", BECDSA::PrivateKeyImportPKCS8);
  Nan::Export(obj, "privateKeyTweakAdd", BECDSA::PrivateKeyTweakAdd);
  Nan::Export(obj, "privateKeyTweakMul", BECDSA::PrivateKeyTweakMul);
  Nan::Export(obj, "privateKeyReduce", BECDSA::PrivateKeyReduce);
  Nan::Export(obj, "privateKeyNegate", BECDSA::PrivateKeyNegate);
  Nan::Export(obj, "privateKeyInvert", BECDSA::PrivateKeyInvert);
  Nan::Export(obj, "publicKeyCreate", BECDSA::PublicKeyCreate);
  Nan::Export(obj, "publicKeyConvert", BECDSA::PublicKeyConvert);
  Nan::Export(obj, "publicKeyVerify", BECDSA::PublicKeyVerify);
  Nan::Export(obj, "publicKeyExportSPKI", BECDSA::PublicKeyExportSPKI);
  Nan::Export(obj, "publicKeyImportSPKI", BECDSA::PublicKeyImportSPKI);
  Nan::Export(obj, "publicKeyTweakAdd", BECDSA::PublicKeyTweakAdd);
  Nan::Export(obj, "publicKeyTweakMul", BECDSA::PublicKeyTweakMul);
  Nan::Export(obj, "publicKeyAdd", BECDSA::PublicKeyAdd);
  Nan::Export(obj, "publicKeyCombine", BECDSA::PublicKeyCombine);
  Nan::Export(obj, "publicKeyNegate", BECDSA::PublicKeyNegate);
  Nan::Export(obj, "signatureNormalize", BECDSA::SignatureNormalize);
  Nan::Export(obj, "signatureNormalizeDER", BECDSA::SignatureNormalizeDER);
  Nan::Export(obj, "signatureExport", BECDSA::SignatureExport);
  Nan::Export(obj, "signatureImport", BECDSA::SignatureImport);
  Nan::Export(obj, "isLowS", BECDSA::IsLowS);
  Nan::Export(obj, "isLowDER", BECDSA::IsLowDER);
  Nan::Export(obj, "sign", BECDSA::Sign);
  Nan::Export(obj, "signRecoverable", BECDSA::SignRecoverable);
  Nan::Export(obj, "signDER", BECDSA::SignDER);
  Nan::Export(obj, "signRecoverableDER", BECDSA::SignRecoverableDER);
  Nan::Export(obj, "verify", BECDSA::Verify);
  Nan::Export(obj, "verifyDER", BECDSA::VerifyDER);
  Nan::Export(obj, "recover", BECDSA::Recover);
  Nan::Export(obj, "recoverDER", BECDSA::RecoverDER);
  Nan::Export(obj, "derive", BECDSA::Derive);
  Nan::Export(obj, "schnorrSign", BECDSA::SchnorrSign);
  Nan::Export(obj, "schnorrVerify", BECDSA::SchnorrVerify);
  Nan::Export(obj, "schnorrVerifyBatch", BECDSA::SchnorrVerifyBatch);

  Nan::Set(target, Nan::New("ecdsa").ToLocalChecked(), obj);
}

NAN_METHOD(BECDSA::Size) {
  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.size() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  int size = bcrypto_ecdsa_field_length(type);

  return info.GetReturnValue().Set(Nan::New<v8::Number>(size));
}

NAN_METHOD(BECDSA::Bits) {
  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.bits() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  int bits = bcrypto_ecdsa_field_bits(type);

  return info.GetReturnValue().Set(Nan::New<v8::Number>(bits));
}

NAN_METHOD(BECDSA::PrivateKeyGenerate) {
  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.bits() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t size = bcrypto_ecdsa_scalar_length(type);
  uint8_t priv[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];

  if (!bcrypto_ecdsa_privkey_generate(type, priv))
    return Nan::ThrowError("Could not generate key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)priv, size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyVerify) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.privateKeyVerify() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != bcrypto_ecdsa_scalar_length(type))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = bcrypto_ecdsa_privkey_verify(type, priv);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::PrivateKeyExport) {
  return Nan::ThrowError("ecdsa.privateKeyExport() requires arguments.");
}

NAN_METHOD(BECDSA::PrivateKeyImport) {
  return Nan::ThrowError("ecdsa.privateKeyImport() requires arguments.");
}

NAN_METHOD(BECDSA::PrivateKeyExportPKCS8) {
  return Nan::ThrowError("ecdsa.privateKeyExportPKCS8() requires arguments.");
}

NAN_METHOD(BECDSA::PrivateKeyImportPKCS8) {
  return Nan::ThrowError("ecdsa.privateKeyImportPKCS8() requires arguments.");
}

NAN_METHOD(BECDSA::PrivateKeyTweakAdd) {
  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.privateKeyTweakAdd() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t size = bcrypto_ecdsa_scalar_length(type);

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  if (priv_len != size || tweak_len != size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];

  if (!bcrypto_ecdsa_privkey_tweak_add(type, out, priv, tweak))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyTweakMul) {
  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.privateKeyTweakMul() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t size = bcrypto_ecdsa_scalar_length(type);

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  if (priv_len != size || tweak_len != size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];

  if (!bcrypto_ecdsa_privkey_tweak_mul(type, out, priv, tweak))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyReduce) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.privateKeyReduce() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t size = bcrypto_ecdsa_scalar_length(type);

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  uint8_t out[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];

  if (!bcrypto_ecdsa_privkey_reduce(type, out, priv, priv_len))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyNegate) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.privateKeyNegate() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t size = bcrypto_ecdsa_scalar_length(type);

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];

  if (!bcrypto_ecdsa_privkey_negate(type, out, priv))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyInvert) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.privateKeyInvert() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t size = bcrypto_ecdsa_scalar_length(type);

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_SCALAR_SIZE];

  if (!bcrypto_ecdsa_privkey_invert(type, out, priv))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyCreate) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.publicKeyCreate() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t size = bcrypto_ecdsa_scalar_length(type);

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  int compress = 1;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[2]).FromJust();
  }

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_pubkey_create(type, out, &out_len, priv, compress))
    return Nan::ThrowError("Could not create key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyConvert) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.publicKeyConvert() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  int compress = 1;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[2]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_pubkey_convert(type, out, &out_len,
                                    pub, pub_len, compress)) {
    return Nan::ThrowError("Invalid public key.");
  }

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyVerify) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.publicKeyVerify() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (!bcrypto_ecdsa_pubkey_verify(type, pub, pub_len))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(true));
}

NAN_METHOD(BECDSA::PublicKeyExportSPKI) {
  return Nan::ThrowError("ecdsa.privateKeyExportPKCS8() requires arguments.");
}

NAN_METHOD(BECDSA::PublicKeyImportSPKI) {
  return Nan::ThrowError("ecdsa.privateKeyImportPKCS8() requires arguments.");
}

NAN_METHOD(BECDSA::PublicKeyTweakAdd) {
  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.publicKeyTweakAdd() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t size = bcrypto_ecdsa_scalar_length(type);

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int compress = 1;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[3]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  if (tweak_len != size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_pubkey_tweak_add(type, out, &out_len,
                                      pub, pub_len, tweak, compress)) {
    return Nan::ThrowError("Could not tweak public key.");
  }

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyTweakMul) {
  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.publicKeyTweakMul() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t size = bcrypto_ecdsa_scalar_length(type);

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int compress = 1;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[3]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  if (tweak_len != size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_pubkey_tweak_mul(type, out, &out_len,
                                      pub, pub_len, tweak, compress)) {
    return Nan::ThrowError("Could not tweak public key.");
  }

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyAdd) {
  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.publicKeyAdd() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();

  v8::Local<v8::Object> p1buf = info[1].As<v8::Object>();
  v8::Local<v8::Object> p2buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(p1buf)
      || !node::Buffer::HasInstance(p2buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int compress = 1;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("First argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[3]).FromJust();
  }

  const uint8_t *pub1 = (const uint8_t *)node::Buffer::Data(p1buf);
  size_t pub1_len = node::Buffer::Length(p1buf);

  const uint8_t *pub2 = (const uint8_t *)node::Buffer::Data(p2buf);
  size_t pub2_len = node::Buffer::Length(p2buf);

  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_pubkey_add(type, out, &out_len,
                                pub1, pub1_len,
                                pub2, pub2_len,
                                compress)) {
    return Nan::ThrowError("Could not tweak public key.");
  }

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyCombine) {
  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.publicKeyCombine() requires arguments.");

  if (!info[1]->IsArray())
    return Nan::ThrowTypeError("First argument must be an array.");

  v8::Local<v8::Array> batch = info[1].As<v8::Array>();

  size_t len = (size_t)batch->Length();

  if (len == 0)
    return Nan::ThrowError("Invalid point.");

  int compress = 1;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[2]).FromJust();
  }

  const uint8_t **pubs =
    (const uint8_t **)malloc(len * sizeof(uint8_t *));

  if (pubs == NULL)
    return Nan::ThrowError("Allocation failed.");

  size_t *pub_lens = (size_t *)malloc(len * sizeof(size_t));

  if (pubs == NULL) {
    free(pubs);
    return Nan::ThrowError("Allocation failed.");
  }

  for (size_t i = 0; i < len; i++) {
    v8::Local<v8::Object> pbuf = Nan::Get(batch, i).ToLocalChecked()
                                                   .As<v8::Object>();

    if (!node::Buffer::HasInstance(pbuf)) {
      free(pubs);
      free(pub_lens);
      return Nan::ThrowTypeError("Public key must be a buffer.");
    }

    const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
    size_t pub_len = node::Buffer::Length(pbuf);

    pubs[i] = pub;
    pub_lens[i] = pub_len;
  }

  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_pubkey_combine(type, out, &out_len,
                                    pubs, pub_lens, len,
                                    compress)) {
    free(pubs);
    free(pub_lens);
    return Nan::ThrowError("Could not tweak public key.");
  }

  free(pubs);
  free(pub_lens);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyNegate) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.publicKeyNegate() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  int compress = 1;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[2]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_pubkey_negate(type, out, &out_len, pub, pub_len, compress))
    return Nan::ThrowError("Could not tweak public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignatureNormalize) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.signatureNormalize() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t size = bcrypto_ecdsa_sig_length(type);

  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  if (sig_len != size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_SIG_SIZE];

  if (!bcrypto_ecdsa_sig_normalize(type, out, sig))
    return Nan::ThrowError("Invalid signature.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, size).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignatureNormalizeDER) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.signatureNormalizeDER() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();

  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  if (sig_len == 0)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_DER_SIZE];
  size_t out_len = BCRYPTO_ECDSA_MAX_DER_SIZE;

  if (!bcrypto_ecdsa_sig_normalize_der(type, out, &out_len, sig, sig_len))
    return Nan::ThrowError("Invalid signature.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignatureExport) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.signatureExport() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t size = bcrypto_ecdsa_sig_length(type);

  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  if (sig_len != size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_DER_SIZE];
  size_t out_len = BCRYPTO_ECDSA_MAX_DER_SIZE;

  if (!bcrypto_ecdsa_sig_export(type, out, &out_len, sig))
    return Nan::ThrowError("Serialization failed.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignatureImport) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.signatureImport() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t size = bcrypto_ecdsa_sig_length(type);

  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  uint8_t out[BCRYPTO_ECDSA_MAX_SIG_SIZE];

  if (!bcrypto_ecdsa_sig_import(type, out, sig, sig_len))
    return Nan::ThrowError("Invalid signature.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, size).ToLocalChecked());
}

NAN_METHOD(BECDSA::IsLowS) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.isLowS() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t size = bcrypto_ecdsa_sig_length(type);

  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  if (sig_len != size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = bcrypto_ecdsa_sig_low_s(type, sig);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::IsLowDER) {
  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.isLowDER() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();

  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  int result = bcrypto_ecdsa_sig_low_der(type, sig, sig_len);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::Sign) {
  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.sign() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t scalar_size = bcrypto_ecdsa_scalar_length(type);
  size_t sig_size = bcrypto_ecdsa_sig_length(type);

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_SIG_SIZE];

  if (!bcrypto_ecdsa_sign(type, out, msg, msg_len, priv))
    return Nan::ThrowError("Could not sign.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, sig_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignRecoverable) {
  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.signRecoverable() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t scalar_size = bcrypto_ecdsa_scalar_length(type);
  size_t sig_size = bcrypto_ecdsa_sig_length(type);

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_SIG_SIZE];
  int param;

  if (!bcrypto_ecdsa_sign_recoverable(type, out, &param, msg, msg_len, priv))
    return Nan::ThrowError("Could not sign.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0, Nan::CopyBuffer((char *)out, sig_size).ToLocalChecked());
  Nan::Set(ret, 1, Nan::New<v8::Number>(param));

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BECDSA::SignDER) {
  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.signDER() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t scalar_size = bcrypto_ecdsa_scalar_length(type);

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_DER_SIZE];
  size_t out_len = BCRYPTO_ECDSA_MAX_DER_SIZE;

  if (!bcrypto_ecdsa_sign_der(type, out, &out_len, msg, msg_len, priv))
    return Nan::ThrowError("Could not sign.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignRecoverableDER) {
  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.signRecoverableDER() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t scalar_size = bcrypto_ecdsa_scalar_length(type);

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_DER_SIZE];
  size_t out_len = BCRYPTO_ECDSA_MAX_DER_SIZE;
  int param;

  if (!bcrypto_ecdsa_sign_recoverable_der(type, out, &out_len,
                                          &param, msg, msg_len, priv)) {
    return Nan::ThrowError("Could not sign.");
  }

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0, Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
  Nan::Set(ret, 1, Nan::New<v8::Number>(param));

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BECDSA::Verify) {
  if (info.Length() < 4)
    return Nan::ThrowError("ecdsa.verify() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t sig_size = bcrypto_ecdsa_sig_length(type);

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[3].As<v8::Object>();

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

  if (sig_len != sig_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = bcrypto_ecdsa_verify(type, msg, msg_len, sig, pub, pub_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::VerifyDER) {
  if (info.Length() < 4)
    return Nan::ThrowError("ecdsa.verify() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[3].As<v8::Object>();

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

  int result = bcrypto_ecdsa_verify_der(type, msg, msg_len,
                                              sig, sig_len,
                                              pub, pub_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::Recover) {
  if (info.Length() < 4)
    return Nan::ThrowError("ecdsa.recover() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t sig_size = bcrypto_ecdsa_sig_length(type);

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a number.");

  int param = (int)Nan::To<uint32_t>(info[3]).FromJust();

  if (param < 0 || (param & 3) != param)
    return Nan::ThrowTypeError("Invalid recovery parameter.");

  int compress = 1;

  if (info.Length() > 4 && !IsNull(info[4])) {
    if (!info[4]->IsBoolean())
      return Nan::ThrowTypeError("Fifth argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[4]).FromJust();
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  if (sig_len != sig_size)
    return info.GetReturnValue().Set(Nan::Null());

  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_recover(type, out, &out_len,
                             msg, msg_len, sig,
                             param, compress)) {
    return info.GetReturnValue().Set(Nan::Null());
  }

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::RecoverDER) {
  if (info.Length() < 4)
    return Nan::ThrowError("ecdsa.recover() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a number.");

  int param = (int)Nan::To<uint32_t>(info[3]).FromJust();

  if (param < 0 || (param & 3) != param)
    return Nan::ThrowTypeError("Invalid recovery parameter.");

  int compress = 1;

  if (info.Length() > 4 && !IsNull(info[4])) {
    if (!info[4]->IsBoolean())
      return Nan::ThrowTypeError("Fifth argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[4]).FromJust();
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_recover_der(type,
                                 out, &out_len,
                                 msg, msg_len,
                                 sig, sig_len,
                                 param, compress)) {
    return info.GetReturnValue().Set(Nan::Null());
  }

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::Derive) {
  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.derive() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t scalar_size = bcrypto_ecdsa_scalar_length(type);

  v8::Local<v8::Object> kbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int compress = 1;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[3]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t pub_len = node::Buffer::Length(kbuf);

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (!bcrypto_ecdsa_derive(type, out, &out_len, pub, pub_len, priv, compress))
    return Nan::ThrowError("Could not perform ECDH.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::SchnorrSign) {
  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.schnorrSign() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t scalar_size = bcrypto_ecdsa_scalar_length(type);
  size_t sig_size = bcrypto_ecdsa_sig_length(type);

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  if (type == BCRYPTO_CURVE_P224)
    return Nan::ThrowError("Schnorr is not supported for curve.");

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (msg_len != 32 || priv_len != scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  uint8_t out[BCRYPTO_ECDSA_MAX_SIG_SIZE];

  if (!bcrypto_schnorr_sign(type, out, msg, priv))
    return Nan::ThrowError("Could not sign.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, sig_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::SchnorrVerify) {
  if (info.Length() < 4)
    return Nan::ThrowError("ecdsa.schnorrVerify() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t sig_size = bcrypto_ecdsa_sig_length(type);

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  if (type == BCRYPTO_CURVE_P224)
    return Nan::ThrowError("Schnorr is not supported for curve.");

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (msg_len != 32 || sig_len != sig_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = bcrypto_schnorr_verify(type, msg, sig, pub, pub_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::SchnorrVerifyBatch) {
  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.schnorrVerifyBatch() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsArray())
    return Nan::ThrowTypeError("First argument must be an array.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  size_t sig_size = bcrypto_ecdsa_sig_length(type);

  if (type == BCRYPTO_CURVE_P224)
    return Nan::ThrowError("Schnorr is not supported for curve.");

  v8::Local<v8::Array> batch = info[1].As<v8::Array>();

  size_t len = (size_t)batch->Length();

  if (len == 0)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(true));

  const uint8_t **msgs =
    (const uint8_t **)malloc(len * sizeof(const uint8_t *));

  if (msgs == NULL)
    return Nan::ThrowError("Allocation failed.");

  const uint8_t **sigs =
    (const uint8_t **)malloc(len * sizeof(const uint8_t *));

  if (sigs == NULL) {
    free(msgs);
    return Nan::ThrowError("Allocation failed.");
  }

  const uint8_t **pubs =
    (const uint8_t **)malloc(len * sizeof(const uint8_t *));

  if (pubs == NULL) {
    free(msgs);
    free(sigs);
    return Nan::ThrowError("Allocation failed.");
  }

  size_t *pub_lens = (size_t *)malloc(len * sizeof(size_t));

  if (pubs == NULL) {
    free(msgs);
    free(sigs);
    free(pubs);
    return Nan::ThrowError("Allocation failed.");
  }

#define FREE_BATCH (free(msgs), free(sigs), free(pubs), free(pub_lens))

  for (size_t i = 0; i < len; i++) {
    if (!Nan::Get(batch, i).ToLocalChecked()->IsArray()) {
      FREE_BATCH;
      return Nan::ThrowTypeError("Item must be an array.");
    }

    v8::Local<v8::Array> item = Nan::Get(batch, i).ToLocalChecked()
                                                  .As<v8::Array>();

    if (item->Length() != 3) {
      FREE_BATCH;
      return Nan::ThrowError("Item must consist of 3 members.");
    }

    v8::Local<v8::Object> mbuf = Nan::Get(item, 0).ToLocalChecked()
                                                  .As<v8::Object>();
    v8::Local<v8::Object> sbuf = Nan::Get(item, 1).ToLocalChecked()
                                                  .As<v8::Object>();
    v8::Local<v8::Object> pbuf = Nan::Get(item, 2).ToLocalChecked()
                                                  .As<v8::Object>();

    if (!node::Buffer::HasInstance(mbuf)
        || !node::Buffer::HasInstance(sbuf)
        || !node::Buffer::HasInstance(pbuf)) {
      FREE_BATCH;
      return Nan::ThrowTypeError("Values must be buffers.");
    }

    const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
    size_t msg_len = node::Buffer::Length(mbuf);

    const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
    size_t sig_len = node::Buffer::Length(sbuf);

    const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
    size_t pub_len = node::Buffer::Length(pbuf);

    if (msg_len != 32 || sig_len != sig_size) {
      FREE_BATCH;
      return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
    }

    msgs[i] = msg;
    sigs[i] = sig;
    pubs[i] = pub;
    pub_lens[i] = pub_len;
  }

  int result = bcrypto_schnorr_batch_verify(type, msgs, sigs,
                                            pubs, pub_lens, len);

  FREE_BATCH;

#undef FREE_BATCH

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result == 1));
}
