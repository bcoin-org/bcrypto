#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "dsa/dsa.h"
#include "dsa.h"
#include "dsa_async.h"

void
BDSA::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "paramsGenerate", BDSA::ParamsGenerate);
  Nan::Export(obj, "paramsGenerateAsync", BDSA::ParamsGenerateAsync);
  Nan::Export(obj, "paramsVerify", BDSA::ParamsVerify);
  Nan::Export(obj, "paramsExport", BDSA::ParamsExport);
  Nan::Export(obj, "paramsImport", BDSA::ParamsImport);
  Nan::Export(obj, "privateKeyCreate", BDSA::PrivateKeyCreate);
  Nan::Export(obj, "privateKeyCompute", BDSA::PrivateKeyCompute);
  Nan::Export(obj, "privateKeyVerify", BDSA::PrivateKeyVerify);
  Nan::Export(obj, "privateKeyExport", BDSA::PrivateKeyExport);
  Nan::Export(obj, "privateKeyImport", BDSA::PrivateKeyImport);
  Nan::Export(obj, "privateKeyExportPKCS8", BDSA::PrivateKeyExportPKCS8);
  Nan::Export(obj, "privateKeyImportPKCS8", BDSA::PrivateKeyImportPKCS8);
  Nan::Export(obj, "publicKeyVerify", BDSA::PublicKeyVerify);
  Nan::Export(obj, "publicKeyExport", BDSA::PublicKeyExport);
  Nan::Export(obj, "publicKeyImport", BDSA::PublicKeyImport);
  Nan::Export(obj, "publicKeyExportSPKI", BDSA::PublicKeyExportSPKI);
  Nan::Export(obj, "publicKeyImportSPKI", BDSA::PublicKeyImportSPKI);
  Nan::Export(obj, "signatureExport", BDSA::SignatureExport);
  Nan::Export(obj, "signatureImport", BDSA::SignatureImport);
  Nan::Export(obj, "sign", BDSA::Sign);
  Nan::Export(obj, "signDER", BDSA::SignDER);
  Nan::Export(obj, "verify", BDSA::Verify);
  Nan::Export(obj, "verifyDER", BDSA::VerifyDER);
  Nan::Export(obj, "derive", BDSA::Derive);

  Nan::Set(target, Nan::New("dsa").ToLocalChecked(), obj);
}

NAN_METHOD(BDSA::ParamsGenerate) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.paramsGenerate() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();

  bcrypto_dsa_key_t key;
  bcrypto_dsa_key_init(&key);

  if (!bcrypto_dsa_params_generate(&key, (int)bits)) {
    bcrypto_dsa_key_uninit(&key);
    return Nan::ThrowTypeError("Could not generate key.");
  }

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)key.pd, key.pl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)key.qd, key.ql).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)key.gd, key.gl).ToLocalChecked());

  bcrypto_dsa_key_uninit(&key);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BDSA::ParamsGenerateAsync) {
  if (info.Length() < 2)
    return Nan::ThrowError("dsa.paramsGenerateAsync() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsFunction())
    return Nan::ThrowTypeError("Second argument must be a function.");

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();

  v8::Local<v8::Function> callback = info[1].As<v8::Function>();

  BDSAWorker *worker = new BDSAWorker(
    (int)bits,
    new Nan::Callback(callback)
  );

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(BDSA::ParamsVerify) {
  if (info.Length() < 3)
    return Nan::ThrowError("dsa.paramsVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t key;
  bcrypto_dsa_key_init(&key);

  key.pd = (uint8_t *)node::Buffer::Data(pbuf);
  key.pl = node::Buffer::Length(pbuf);

  key.qd = (uint8_t *)node::Buffer::Data(qbuf);
  key.ql = node::Buffer::Length(qbuf);

  key.gd = (uint8_t *)node::Buffer::Data(gbuf);
  key.gl = node::Buffer::Length(gbuf);

  int result = bcrypto_dsa_params_verify(&key);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BDSA::ParamsExport) {
  return Nan::ThrowError("dsa.paramsExport() requires arguments.");
}

NAN_METHOD(BDSA::ParamsImport) {
  return Nan::ThrowError("dsa.paramsImport() requires arguments.");
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

  bcrypto_dsa_key_t key;
  bcrypto_dsa_key_init(&key);

  key.pd = (uint8_t *)node::Buffer::Data(pbuf);
  key.pl = node::Buffer::Length(pbuf);

  key.qd = (uint8_t *)node::Buffer::Data(qbuf);
  key.ql = node::Buffer::Length(qbuf);

  key.gd = (uint8_t *)node::Buffer::Data(gbuf);
  key.gl = node::Buffer::Length(gbuf);

  if (!bcrypto_dsa_privkey_create(&key, &key)) {
    bcrypto_dsa_key_uninit(&key);
    return Nan::ThrowError("Could not generate key.");
  }

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)key.pd, key.pl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)key.qd, key.ql).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)key.gd, key.gl).ToLocalChecked());
  Nan::Set(ret, 3, Nan::CopyBuffer((char *)key.yd, key.yl).ToLocalChecked());
  Nan::Set(ret, 4, Nan::CopyBuffer((char *)key.xd, key.xl).ToLocalChecked());

  bcrypto_dsa_key_uninit(&key);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BDSA::PrivateKeyCompute) {
  if (info.Length() < 5)
    return Nan::ThrowError("dsa.privateKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> xbuf = info[4].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)
      || !node::Buffer::HasInstance(xbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t key;
  bcrypto_dsa_key_init(&key);

  key.pd = (uint8_t *)node::Buffer::Data(pbuf);
  key.pl = node::Buffer::Length(pbuf);

  key.qd = (uint8_t *)node::Buffer::Data(qbuf);
  key.ql = node::Buffer::Length(qbuf);

  key.gd = (uint8_t *)node::Buffer::Data(gbuf);
  key.gl = node::Buffer::Length(gbuf);

  key.yd = (uint8_t *)node::Buffer::Data(ybuf);
  key.yl = node::Buffer::Length(ybuf);

  key.xd = (uint8_t *)node::Buffer::Data(xbuf);
  key.xl = node::Buffer::Length(xbuf);

  size_t y_len = bcrypto_dsa_key_psize(&key);
  uint8_t *y = (uint8_t *)malloc(y_len);

  if (y == NULL)
    return Nan::ThrowError("Could not compute private key.");

  int result = bcrypto_dsa_privkey_compute(y, &y_len, &key);

  if (result == 0) {
    free(y);
    return Nan::ThrowError("Could not compute private key.");
  }

  if (result == 2)
    return info.GetReturnValue().Set(Nan::Null());

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)y, y_len).ToLocalChecked());
}

NAN_METHOD(BDSA::PrivateKeyVerify) {
  if (info.Length() < 5)
    return Nan::ThrowError("dsa.privateKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> xbuf = info[4].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)
      || !node::Buffer::HasInstance(xbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t key;
  bcrypto_dsa_key_init(&key);

  key.pd = (uint8_t *)node::Buffer::Data(pbuf);
  key.pl = node::Buffer::Length(pbuf);

  key.qd = (uint8_t *)node::Buffer::Data(qbuf);
  key.ql = node::Buffer::Length(qbuf);

  key.gd = (uint8_t *)node::Buffer::Data(gbuf);
  key.gl = node::Buffer::Length(gbuf);

  key.yd = (uint8_t *)node::Buffer::Data(ybuf);
  key.yl = node::Buffer::Length(ybuf);

  key.xd = (uint8_t *)node::Buffer::Data(xbuf);
  key.xl = node::Buffer::Length(xbuf);

  int result = bcrypto_dsa_privkey_verify(&key);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BDSA::PrivateKeyExport) {
  return Nan::ThrowError("dsa.privateKeyExport() requires arguments.");
}

NAN_METHOD(BDSA::PrivateKeyImport) {
  return Nan::ThrowError("dsa.privateKeyImport() requires arguments.");
}

NAN_METHOD(BDSA::PrivateKeyExportPKCS8) {
  return Nan::ThrowError("dsa.privateKeyExportPKCS8() requires arguments.");
}

NAN_METHOD(BDSA::PrivateKeyImportPKCS8) {
  return Nan::ThrowError("dsa.privateKeyImportPKCS8() requires arguments.");
}

NAN_METHOD(BDSA::PublicKeyVerify) {
  if (info.Length() < 4)
    return Nan::ThrowError("dsa.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t key;
  bcrypto_dsa_key_init(&key);

  key.pd = (uint8_t *)node::Buffer::Data(pbuf);
  key.pl = node::Buffer::Length(pbuf);

  key.qd = (uint8_t *)node::Buffer::Data(qbuf);
  key.ql = node::Buffer::Length(qbuf);

  key.gd = (uint8_t *)node::Buffer::Data(gbuf);
  key.gl = node::Buffer::Length(gbuf);

  key.yd = (uint8_t *)node::Buffer::Data(ybuf);
  key.yl = node::Buffer::Length(ybuf);

  int result = bcrypto_dsa_pubkey_verify(&key);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BDSA::PublicKeyExport) {
  return Nan::ThrowError("dsa.publicKeyExport() requires arguments.");
}

NAN_METHOD(BDSA::PublicKeyImport) {
  return Nan::ThrowError("dsa.publicKeyImport() requires arguments.");
}

NAN_METHOD(BDSA::PublicKeyExportSPKI) {
  return Nan::ThrowError("dsa.publicKeyExportSPKI() requires arguments.");
}

NAN_METHOD(BDSA::PublicKeyImportSPKI) {
  return Nan::ThrowError("dsa.publicKeyImportSPKI() requires arguments.");
}

NAN_METHOD(BDSA::SignatureExport) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.signatureExport() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  size_t size = 0;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsNumber())
      return Nan::ThrowTypeError("Second argument must be a number.");

    size = Nan::To<uint32_t>(info[1]).FromJust();
  }

  uint8_t out[BCRYPTO_DSA_MAX_DER_SIZE];
  size_t out_len;

  if (!bcrypto_dsa_sig_export(out, &out_len, sig, sig_len, size))
    return Nan::ThrowError("Could not export signature.");

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::SignatureImport) {
  if (info.Length() < 2)
    return Nan::ThrowError("dsa.signatureImport() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  uint32_t size = Nan::To<uint32_t>(info[1]).FromJust();

  size_t out_len = size * 2;
  uint8_t out[BCRYPTO_DSA_MAX_SIG_SIZE];

  if (!bcrypto_dsa_sig_import(out, sig, sig_len, size))
    return Nan::ThrowError("Could not import signature.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], out_len).ToLocalChecked());
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

  bcrypto_dsa_key_t key;
  bcrypto_dsa_key_init(&key);

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  key.pd = (uint8_t *)node::Buffer::Data(pbuf);
  key.pl = node::Buffer::Length(pbuf);

  key.qd = (uint8_t *)node::Buffer::Data(qbuf);
  key.ql = node::Buffer::Length(qbuf);

  key.gd = (uint8_t *)node::Buffer::Data(gbuf);
  key.gl = node::Buffer::Length(gbuf);

  key.yd = (uint8_t *)node::Buffer::Data(ybuf);
  key.yl = node::Buffer::Length(ybuf);

  key.xd = (uint8_t *)node::Buffer::Data(xbuf);
  key.xl = node::Buffer::Length(xbuf);

  size_t out_len = bcrypto_dsa_sig_size(&key);
  uint8_t out[BCRYPTO_DSA_MAX_SIG_SIZE];

  if (!bcrypto_dsa_sign(out, md, ml, &key))
    return Nan::ThrowError("Could not sign message.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::SignDER) {
  if (info.Length() < 6)
    return Nan::ThrowError("dsa.signDER() requires arguments.");

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

  bcrypto_dsa_key_t key;
  bcrypto_dsa_key_init(&key);

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  key.pd = (uint8_t *)node::Buffer::Data(pbuf);
  key.pl = node::Buffer::Length(pbuf);

  key.qd = (uint8_t *)node::Buffer::Data(qbuf);
  key.ql = node::Buffer::Length(qbuf);

  key.gd = (uint8_t *)node::Buffer::Data(gbuf);
  key.gl = node::Buffer::Length(gbuf);

  key.yd = (uint8_t *)node::Buffer::Data(ybuf);
  key.yl = node::Buffer::Length(ybuf);

  key.xd = (uint8_t *)node::Buffer::Data(xbuf);
  key.xl = node::Buffer::Length(xbuf);

  uint8_t out[BCRYPTO_DSA_MAX_DER_SIZE];
  size_t out_len;

  if (!bcrypto_dsa_sign_der(out, &out_len, md, ml, &key))
    return Nan::ThrowError("Could not sign message.");

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::Verify) {
  if (info.Length() < 6)
    return Nan::ThrowError("dsa.verify() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[5].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  const uint8_t *sd = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sl = node::Buffer::Length(sbuf);

  bcrypto_dsa_key_t key;
  bcrypto_dsa_key_init(&key);

  key.pd = (uint8_t *)node::Buffer::Data(pbuf);
  key.pl = node::Buffer::Length(pbuf);

  key.qd = (uint8_t *)node::Buffer::Data(qbuf);
  key.ql = node::Buffer::Length(qbuf);

  key.gd = (uint8_t *)node::Buffer::Data(gbuf);
  key.gl = node::Buffer::Length(gbuf);

  key.yd = (uint8_t *)node::Buffer::Data(ybuf);
  key.yl = node::Buffer::Length(ybuf);

  int result = bcrypto_dsa_verify(md, ml, sd, sl, &key);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BDSA::VerifyDER) {
  if (info.Length() < 6)
    return Nan::ThrowError("dsa.verifyDER() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[5].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  const uint8_t *sd = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sl = node::Buffer::Length(sbuf);

  bcrypto_dsa_key_t key;
  bcrypto_dsa_key_init(&key);

  key.pd = (uint8_t *)node::Buffer::Data(pbuf);
  key.pl = node::Buffer::Length(pbuf);

  key.qd = (uint8_t *)node::Buffer::Data(qbuf);
  key.ql = node::Buffer::Length(qbuf);

  key.gd = (uint8_t *)node::Buffer::Data(gbuf);
  key.gl = node::Buffer::Length(gbuf);

  key.yd = (uint8_t *)node::Buffer::Data(ybuf);
  key.yl = node::Buffer::Length(ybuf);

  int result = bcrypto_dsa_verify_der(md, ml, sd, sl, &key);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BDSA::Derive) {
  if (info.Length() < 9)
    return Nan::ThrowError("dsa.derive() requires arguments.");

  v8::Local<v8::Object> ppbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> pqbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pgbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> pybuf = info[3].As<v8::Object>();

  v8::Local<v8::Object> spbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> sqbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> sgbuf = info[6].As<v8::Object>();
  v8::Local<v8::Object> sybuf = info[7].As<v8::Object>();
  v8::Local<v8::Object> sxbuf = info[8].As<v8::Object>();

  if (!node::Buffer::HasInstance(ppbuf)
      || !node::Buffer::HasInstance(pqbuf)
      || !node::Buffer::HasInstance(pgbuf)
      || !node::Buffer::HasInstance(pybuf)
      || !node::Buffer::HasInstance(spbuf)
      || !node::Buffer::HasInstance(sqbuf)
      || !node::Buffer::HasInstance(sgbuf)
      || !node::Buffer::HasInstance(sybuf)
      || !node::Buffer::HasInstance(sxbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t pub;
  bcrypto_dsa_key_init(&pub);

  pub.pd = (uint8_t *)node::Buffer::Data(ppbuf);
  pub.pl = node::Buffer::Length(ppbuf);

  pub.qd = (uint8_t *)node::Buffer::Data(pqbuf);
  pub.ql = node::Buffer::Length(pqbuf);

  pub.gd = (uint8_t *)node::Buffer::Data(pgbuf);
  pub.gl = node::Buffer::Length(pgbuf);

  pub.yd = (uint8_t *)node::Buffer::Data(pybuf);
  pub.yl = node::Buffer::Length(pybuf);

  bcrypto_dsa_key_t priv;
  bcrypto_dsa_key_init(&priv);

  priv.pd = (uint8_t *)node::Buffer::Data(spbuf);
  priv.pl = node::Buffer::Length(spbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(sqbuf);
  priv.ql = node::Buffer::Length(sqbuf);

  priv.gd = (uint8_t *)node::Buffer::Data(sgbuf);
  priv.gl = node::Buffer::Length(sgbuf);

  priv.yd = (uint8_t *)node::Buffer::Data(sybuf);
  priv.yl = node::Buffer::Length(sybuf);

  priv.xd = (uint8_t *)node::Buffer::Data(sxbuf);
  priv.xl = node::Buffer::Length(sxbuf);

  size_t out_len = bcrypto_dsa_key_psize(&pub);
  uint8_t *out = (uint8_t *)malloc(out_len);

  if (out == NULL)
    return Nan::ThrowError("Could not derive key.");

  if (!bcrypto_dsa_derive(out, &out_len, &pub, &priv))
    return Nan::ThrowError("Could not derive key.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}
