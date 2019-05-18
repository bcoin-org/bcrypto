#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "rsa/rsa.h"
#include "rsa.h"
#include "rsa_async.h"

void
BRSA::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "privateKeyGenerate", BRSA::PrivateKeyGenerate);
  Nan::Export(obj, "privateKeyGenerateAsync", BRSA::PrivateKeyGenerateAsync);
  Nan::Export(obj, "privateKeyCompute", BRSA::PrivateKeyCompute);
  Nan::Export(obj, "privateKeyVerify", BRSA::PrivateKeyVerify);
  Nan::Export(obj, "privateKeyExport", BRSA::PrivateKeyExport);
  Nan::Export(obj, "privateKeyImport", BRSA::PrivateKeyImport);
  Nan::Export(obj, "privateKeyExportPKCS8", BRSA::PrivateKeyExportPKCS8);
  Nan::Export(obj, "privateKeyImportPKCS8", BRSA::PrivateKeyImportPKCS8);
  Nan::Export(obj, "publicKeyVerify", BRSA::PublicKeyVerify);
  Nan::Export(obj, "publicKeyExport", BRSA::PublicKeyExport);
  Nan::Export(obj, "publicKeyImport", BRSA::PublicKeyImport);
  Nan::Export(obj, "publicKeyExportSPKI", BRSA::PublicKeyExportSPKI);
  Nan::Export(obj, "publicKeyImportSPKI", BRSA::PublicKeyImportSPKI);
  Nan::Export(obj, "sign", BRSA::Sign);
  Nan::Export(obj, "verify", BRSA::Verify);
  Nan::Export(obj, "encrypt", BRSA::Encrypt);
  Nan::Export(obj, "decrypt", BRSA::Decrypt);
  Nan::Export(obj, "encryptOAEP", BRSA::EncryptOAEP);
  Nan::Export(obj, "decryptOAEP", BRSA::DecryptOAEP);
  Nan::Export(obj, "signPSS", BRSA::SignPSS);
  Nan::Export(obj, "verifyPSS", BRSA::VerifyPSS);
  Nan::Export(obj, "encryptRaw", BRSA::EncryptRaw);
  Nan::Export(obj, "decryptRaw", BRSA::DecryptRaw);
  Nan::Export(obj, "veil", BRSA::Veil);
  Nan::Export(obj, "unveil", BRSA::Unveil);
  Nan::Export(obj, "hasHash", BRSA::HasHash);

  Nan::Set(target, Nan::New("rsa").ToLocalChecked(), obj);
}

NAN_METHOD(BRSA::PrivateKeyGenerate) {
  if (info.Length() < 2)
    return Nan::ThrowError("rsa.privateKeyGenerate() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();
  uint64_t exponent = Nan::To<int64_t>(info[1]).FromJust();

  bcrypto_rsa_key_t key;
  bcrypto_rsa_key_init(&key);

  if (!bcrypto_rsa_privkey_generate(&key, (int)bits, exponent)) {
    bcrypto_rsa_key_uninit(&key);
    return Nan::ThrowError("Could not generate key.");
  }

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)key.nd, key.nl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)key.ed, key.el).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)key.dd, key.dl).ToLocalChecked());
  Nan::Set(ret, 3, Nan::CopyBuffer((char *)key.pd, key.pl).ToLocalChecked());
  Nan::Set(ret, 4, Nan::CopyBuffer((char *)key.qd, key.ql).ToLocalChecked());
  Nan::Set(ret, 5, Nan::CopyBuffer((char *)key.dpd, key.dpl).ToLocalChecked());
  Nan::Set(ret, 6, Nan::CopyBuffer((char *)key.dqd, key.dql).ToLocalChecked());
  Nan::Set(ret, 7, Nan::CopyBuffer((char *)key.qid, key.qil).ToLocalChecked());

  bcrypto_rsa_key_uninit(&key);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BRSA::PrivateKeyGenerateAsync) {
  if (info.Length() < 3)
    return Nan::ThrowError("rsa.privateKeyGenerateAsync() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  if (!info[2]->IsFunction())
    return Nan::ThrowTypeError("Third argument must be a function.");

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();
  uint64_t exponent = Nan::To<int64_t>(info[1]).FromJust();

  v8::Local<v8::Function> callback = info[2].As<v8::Function>();

  BRSAWorker *worker = new BRSAWorker(
    (int)bits,
    exponent,
    new Nan::Callback(callback)
  );

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(BRSA::PrivateKeyCompute) {
  if (info.Length() < 8)
    return Nan::ThrowError("rsa.privateKeyCompute() requires arguments.");

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

  bcrypto_rsa_key_t key;
  bcrypto_rsa_key_init(&key);

  int result = bcrypto_rsa_privkey_compute(&key, &priv);

  if (result == 0) {
    bcrypto_rsa_key_uninit(&key);
    return Nan::ThrowError("Could not compute private key.");
  }

  if (result == 2) {
    bcrypto_rsa_key_uninit(&key);
    return info.GetReturnValue().Set(Nan::Null());
  }

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)key.nd, key.nl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)key.ed, key.el).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)key.dd, key.dl).ToLocalChecked());
  Nan::Set(ret, 3, Nan::CopyBuffer((char *)key.dpd, key.dpl).ToLocalChecked());
  Nan::Set(ret, 4, Nan::CopyBuffer((char *)key.dqd, key.dql).ToLocalChecked());
  Nan::Set(ret, 5, Nan::CopyBuffer((char *)key.qid, key.qil).ToLocalChecked());

  bcrypto_rsa_key_uninit(&key);

  return info.GetReturnValue().Set(ret);
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

  int result = bcrypto_rsa_privkey_verify(&priv);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BRSA::PrivateKeyExport) {
  return Nan::ThrowError("rsa.privateKeyExport() is not implemented.");
}

NAN_METHOD(BRSA::PrivateKeyImport) {
  return Nan::ThrowError("rsa.privateKeyImport() is not implemented.");
}

NAN_METHOD(BRSA::PrivateKeyExportPKCS8) {
  return Nan::ThrowError("rsa.privateKeyExportPKCS8() is not implemented.");
}

NAN_METHOD(BRSA::PrivateKeyImportPKCS8) {
  return Nan::ThrowError("rsa.privateKeyImportPKCS8() is not implemented.");
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

  int result = bcrypto_rsa_pubkey_verify(&pub);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BRSA::PublicKeyExport) {
  return Nan::ThrowError("rsa.publicKeyExport() is not implemented.");
}

NAN_METHOD(BRSA::PublicKeyImport) {
  return Nan::ThrowError("rsa.publicKeyImport() is not implemented.");
}

NAN_METHOD(BRSA::PublicKeyExportSPKI) {
  return Nan::ThrowError("rsa.publicKeyExportSPKI() is not implemented.");
}

NAN_METHOD(BRSA::PublicKeyImportSPKI) {
  return Nan::ThrowError("rsa.publicKeyImportSPKI() is not implemented.");
}

NAN_METHOD(BRSA::Sign) {
  if (info.Length() < 10)
    return Nan::ThrowError("rsa.sign() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();

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
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_rsa_key_t priv;
  bcrypto_rsa_key_init(&priv);

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
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

  size_t sig_len = bcrypto_rsa_key_size(&priv);

  if (sig_len == 0)
    return Nan::ThrowRangeError("Invalid key.");

  uint8_t *sig = (uint8_t *)malloc(sig_len);

  if (sig == NULL)
    return Nan::ThrowError("Allocation failed.");

  if (!bcrypto_rsa_sign(sig, type, md, ml, &priv)) {
    free(sig);
    return Nan::ThrowError("Could not sign message.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)sig, sig_len).ToLocalChecked());
}

NAN_METHOD(BRSA::Verify) {
  if (info.Length() < 5)
    return Nan::ThrowError("rsa.verify() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();

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

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  const uint8_t *sd = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sl = node::Buffer::Length(sbuf);

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  int result = bcrypto_rsa_verify(type, md, ml, sd, sl, &pub);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BRSA::Encrypt) {
  if (info.Length() < 3)
    return Nan::ThrowError("rsa.encrypt() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  size_t ct_len = bcrypto_rsa_key_size(&pub);

  if (ct_len == 0)
    return Nan::ThrowRangeError("Invalid key.");

  uint8_t *ct = (uint8_t *)malloc(ct_len);

  if (ct == NULL)
    return Nan::ThrowError("Allocation failed.");

  if (!bcrypto_rsa_encrypt(ct, md, ml, &pub)) {
    free(ct);
    return Nan::ThrowError("Could not encrypt message.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)ct, ct_len).ToLocalChecked());
}

NAN_METHOD(BRSA::Decrypt) {
  if (info.Length() < 9)
    return Nan::ThrowError("rsa.decrypt() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> dbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> dpbuf = info[6].As<v8::Object>();
  v8::Local<v8::Object> dqbuf = info[7].As<v8::Object>();
  v8::Local<v8::Object> qibuf = info[8].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(nbuf)
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

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
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

  size_t pt_len = bcrypto_rsa_key_size(&priv);

  if (pt_len == 0)
    return Nan::ThrowRangeError("Invalid key.");

  uint8_t *pt = (uint8_t *)malloc(pt_len);

  if (pt == NULL)
    return Nan::ThrowError("Allocation failed.");

  if (!bcrypto_rsa_decrypt(pt, &pt_len, md, ml, &priv)) {
    free(pt);
    return Nan::ThrowError("Could not decrypt message.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)pt, pt_len).ToLocalChecked());
}

NAN_METHOD(BRSA::EncryptOAEP) {
  if (info.Length() < 4)
    return Nan::ThrowError("rsa.encryptOAEP() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  const uint8_t *ld = NULL;
  size_t ll = 0;

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> lbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(lbuf))
      return Nan::ThrowTypeError("Fifth argument must be a buffer.");

    ld = (const uint8_t *)node::Buffer::Data(lbuf);
    ll = node::Buffer::Length(lbuf);
  }

  size_t ct_len = bcrypto_rsa_key_size(&pub);

  if (ct_len == 0)
    return Nan::ThrowRangeError("Invalid key.");

  uint8_t *ct = (uint8_t *)malloc(ct_len);

  if (ct == NULL)
    return Nan::ThrowError("Allocation failed.");

  if (!bcrypto_rsa_encrypt_oaep(ct, type, md, ml, &pub, ld, ll)) {
    free(ct);
    return Nan::ThrowError("Could not encrypt message.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)ct, ct_len).ToLocalChecked());
}

NAN_METHOD(BRSA::DecryptOAEP) {
  if (info.Length() < 10)
    return Nan::ThrowError("rsa.decryptOAEP() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();

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
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_rsa_key_t priv;
  bcrypto_rsa_key_init(&priv);

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
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

  const uint8_t *ld = NULL;
  size_t ll = 0;

  if (info.Length() > 10 && !IsNull(info[10])) {
    v8::Local<v8::Object> lbuf = info[10].As<v8::Object>();

    if (!node::Buffer::HasInstance(lbuf))
      return Nan::ThrowTypeError("Eleventh argument must be a buffer.");

    ld = (const uint8_t *)node::Buffer::Data(lbuf);
    ll = node::Buffer::Length(lbuf);
  }

  size_t pt_len = bcrypto_rsa_key_size(&priv);
  uint8_t *pt = (uint8_t *)malloc(pt_len);

  if (pt_len == 0)
    return Nan::ThrowRangeError("Invalid key.");

  if (pt == NULL)
    return Nan::ThrowError("Allocation failed.");

  if (!bcrypto_rsa_decrypt_oaep(pt, &pt_len, type, md, ml, &priv, ld, ll)) {
    free(pt);
    return Nan::ThrowError("Could not decrypt message.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)pt, pt_len).ToLocalChecked());
}

NAN_METHOD(BRSA::SignPSS) {
  if (info.Length() < 10)
    return Nan::ThrowError("rsa.signPSS() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();

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
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_rsa_key_t priv;
  bcrypto_rsa_key_init(&priv);

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
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

  int salt_len = -1;

  if (info.Length() > 10 && !IsNull(info[10])) {
    if (!info[10]->IsNumber())
      return Nan::ThrowTypeError("Argument must be a number.");

    salt_len = (int)Nan::To<uint32_t>(info[10]).FromJust();
  }

  size_t sig_len = bcrypto_rsa_key_size(&priv);

  if (sig_len == 0)
    return Nan::ThrowRangeError("Invalid key.");

  uint8_t *sig = (uint8_t *)malloc(sig_len);

  if (sig == NULL)
    return Nan::ThrowError("Allocation failed.");

  if (!bcrypto_rsa_sign_pss(sig, type, md, ml, &priv, salt_len)) {
    free(sig);
    return Nan::ThrowError("Could not sign message.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)sig, sig_len).ToLocalChecked());
}

NAN_METHOD(BRSA::VerifyPSS) {
  if (info.Length() < 5)
    return Nan::ThrowError("rsa.verifyPSS() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();

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

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  const uint8_t *sd = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sl = node::Buffer::Length(sbuf);

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  int salt_len = -1;

  if (info.Length() > 5 && !IsNull(info[5])) {
    if (!info[5]->IsNumber())
      return Nan::ThrowTypeError("Sixth argument must be a number.");

    salt_len = (int)Nan::To<uint32_t>(info[5]).FromJust();
  }

  int result = bcrypto_rsa_verify_pss(type, md, ml, sd, sl, &pub, salt_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BRSA::EncryptRaw) {
  if (info.Length() < 3)
    return Nan::ThrowError("rsa.encryptRaw() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  size_t ct_len = bcrypto_rsa_key_size(&pub);

  if (ct_len == 0)
    return Nan::ThrowRangeError("Invalid key.");

  uint8_t *ct = (uint8_t *)malloc(ct_len);

  if (ct == NULL)
    return Nan::ThrowError("Allocation failed.");

  if (!bcrypto_rsa_encrypt_raw(ct, md, ml, &pub)) {
    free(ct);
    return Nan::ThrowError("Could not encrypt message.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)ct, ct_len).ToLocalChecked());
}

NAN_METHOD(BRSA::DecryptRaw) {
  if (info.Length() < 9)
    return Nan::ThrowError("rsa.decryptRaw() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> dbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> dpbuf = info[6].As<v8::Object>();
  v8::Local<v8::Object> dqbuf = info[7].As<v8::Object>();
  v8::Local<v8::Object> qibuf = info[8].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(nbuf)
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

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
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

  size_t pt_len = bcrypto_rsa_key_size(&priv);

  if (pt_len == 0)
    return Nan::ThrowRangeError("Invalid key.");

  uint8_t *pt = (uint8_t *)malloc(pt_len);

  if (pt == NULL)
    return Nan::ThrowError("Allocation failed.");

  if (!bcrypto_rsa_decrypt_raw(pt, md, ml, &priv)) {
    free(pt);
    return Nan::ThrowError("Could not decrypt message.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)pt, pt_len).ToLocalChecked());
}

NAN_METHOD(BRSA::Veil) {
  if (info.Length() < 4)
    return Nan::ThrowError("rsa.veil() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  v8::Local<v8::Object> nbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  size_t bits = (size_t)Nan::To<uint32_t>(info[1]).FromJust();

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  size_t ct_len = (bits + 7) / 8;

  if (ct_len < BCRYPTO_RSA_MIN_BYTES || ct_len > BCRYPTO_RSA_MAX_BYTES)
    return Nan::ThrowRangeError("Invalid bits.");

  uint8_t *ct = (uint8_t *)malloc(ct_len);

  if (ct == NULL)
    return Nan::ThrowError("Could not veil message.");

  if (!bcrypto_rsa_veil(ct, md, ml, bits, &pub)) {
    free(ct);
    return Nan::ThrowError("Could not veil message.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)ct, ct_len).ToLocalChecked());
}

NAN_METHOD(BRSA::Unveil) {
  if (info.Length() < 4)
    return Nan::ThrowError("rsa.unveil() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  v8::Local<v8::Object> nbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  size_t bits = (size_t)Nan::To<uint32_t>(info[1]).FromJust();

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  size_t ct_len = bcrypto_rsa_key_size(&pub);

  if (ct_len == 0)
    return Nan::ThrowRangeError("Invalid key.");

  uint8_t *ct = (uint8_t *)malloc(ct_len);

  if (ct == NULL)
    return Nan::ThrowError("Could not veil message.");

  if (!bcrypto_rsa_unveil(ct, md, ml, bits, &pub)) {
    free(ct);
    return Nan::ThrowError("Could not unveil message.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)ct, ct_len).ToLocalChecked());
}

NAN_METHOD(BRSA::HasHash) {
  if (info.Length() < 1)
    return Nan::ThrowError("rsa.hasHash() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  int result = bcrypto_rsa_has_hash(type);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
