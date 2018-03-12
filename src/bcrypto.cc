/**
 * bcrypto.cc - fast native bindings to crypto functions.
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License)
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <node.h>
#include <nan.h>

#include "openssl/evp.h"
#include "openssl/rand.h"

#include "cipher.h"
#include "chacha20.h"
#include "poly1305.h"
#include "pbkdf2.h"
#include "pbkdf2_async.h"
#include "scrypt.h"
#include "scrypt_async.h"
#include "ripemd160.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "hash160.h"
#include "hash256.h"
#include "keccak.h"
#include "blake2b.h"
#include "bcrypto.h"

NAN_METHOD(pbkdf2) {
  if (info.Length() < 5)
    return Nan::ThrowError("pbkdf2() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  v8::Local<v8::Object> kbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  v8::Local<v8::Object> sbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a number.");

  if (!info[4]->IsNumber())
    return Nan::ThrowTypeError("Fifth argument must be a number.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(kbuf);
  uint32_t datalen = (const uint32_t)node::Buffer::Length(kbuf);
  const uint8_t *salt = (const uint8_t *)node::Buffer::Data(sbuf);
  uint32_t saltlen = (size_t)node::Buffer::Length(sbuf);
  uint32_t iter = info[3]->Uint32Value();
  uint32_t keylen = info[4]->Uint32Value();

  uint8_t *key = (uint8_t *)malloc(keylen);

  if (key == NULL)
    return Nan::ThrowError("Could not allocate key.");

  if (!bcrypto_pbkdf2(name, data, datalen, salt, saltlen, iter, key, keylen))
    return Nan::ThrowError("PBKDF2 failed.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)key, keylen).ToLocalChecked());
}

NAN_METHOD(pbkdf2_async) {
  if (info.Length() < 6)
    return Nan::ThrowError("pbkdf2_async() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  v8::Local<v8::Object> dbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(dbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  v8::Local<v8::Object> sbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a number.");

  if (!info[4]->IsNumber())
    return Nan::ThrowTypeError("Fifth argument must be a number.");

  if (!info[5]->IsFunction())
    return Nan::ThrowTypeError("Sixth argument must be a Function.");

  v8::Local<v8::Function> callback = info[5].As<v8::Function>();

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  const EVP_MD* md = EVP_get_digestbyname(name);

  if (md == NULL)
    return Nan::ThrowTypeError("Could not allocate context.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(dbuf);
  uint32_t datalen = (const uint32_t)node::Buffer::Length(dbuf);
  const uint8_t *salt = (const uint8_t *)node::Buffer::Data(sbuf);
  uint32_t saltlen = (size_t)node::Buffer::Length(sbuf);
  uint32_t iter = info[3]->Uint32Value();
  uint32_t keylen = info[4]->Uint32Value();

  PBKDF2Worker *worker = new PBKDF2Worker(
    dbuf,
    sbuf,
    md,
    data,
    datalen,
    salt,
    saltlen,
    iter,
    keylen,
    new Nan::Callback(callback)
  );

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(scrypt) {
  if (info.Length() < 6)
    return Nan::ThrowError("scrypt() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a number.");

  if (!info[4]->IsNumber())
    return Nan::ThrowTypeError("Fifth argument must be a number.");

  if (!info[5]->IsNumber())
    return Nan::ThrowTypeError("Sixth argument must be a number.");

  const uint8_t *pass = (const uint8_t *)node::Buffer::Data(pbuf);
  const uint32_t passlen = (const uint32_t)node::Buffer::Length(pbuf);
  const uint8_t *salt = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t saltlen = (size_t)node::Buffer::Length(sbuf);
  uint64_t N = (uint64_t)info[2]->IntegerValue();
  uint64_t r = (uint64_t)info[3]->IntegerValue();
  uint64_t p = (uint64_t)info[4]->IntegerValue();
  size_t keylen = (size_t)info[5]->IntegerValue();

  uint8_t *key = (uint8_t *)malloc(keylen);

  if (key == NULL)
    return Nan::ThrowError("Could not allocate key.");

  if (!bcrypto_scrypt(pass, passlen, salt, saltlen, N, r, p, key, keylen))
    return Nan::ThrowError("Scrypt failed.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)key, keylen).ToLocalChecked());
}

NAN_METHOD(scrypt_async) {
  if (info.Length() < 6)
    return Nan::ThrowError("scrypt_async() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a number.");

  if (!info[4]->IsNumber())
    return Nan::ThrowTypeError("Fifth argument must be a number.");

  if (!info[5]->IsNumber())
    return Nan::ThrowTypeError("Sixth argument must be a number.");

  if (!info[6]->IsFunction())
    return Nan::ThrowTypeError("Seventh argument must be a Function.");

  v8::Local<v8::Function> callback = info[6].As<v8::Function>();

  const uint8_t *pass = (const uint8_t *)node::Buffer::Data(pbuf);
  const uint32_t passlen = (const uint32_t)node::Buffer::Length(pbuf);
  const uint8_t *salt = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t saltlen = (size_t)node::Buffer::Length(sbuf);
  uint64_t N = (uint64_t)info[2]->IntegerValue();
  uint64_t r = (uint64_t)info[3]->IntegerValue();
  uint64_t p = (uint64_t)info[4]->IntegerValue();
  size_t keylen = (size_t)info[5]->IntegerValue();

  ScryptWorker* worker = new ScryptWorker(
    pbuf,
    sbuf,
    pass,
    passlen,
    salt,
    saltlen,
    N,
    r,
    p,
    keylen,
    new Nan::Callback(callback)
  );

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(cleanse) {
  if (info.Length() < 1)
    return Nan::ThrowError("cleanse() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  OPENSSL_cleanse((void *)data, len);
}

NAN_METHOD(encipher) {
  if (info.Length() < 3)
    return Nan::ThrowError("encipher() requires arguments.");

  if (!node::Buffer::HasInstance(info[0]))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(info[1]))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  if (!node::Buffer::HasInstance(info[2]))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  v8::Local<v8::Object> bdata = info[0].As<v8::Object>();
  v8::Local<v8::Object> bkey = info[1].As<v8::Object>();
  v8::Local<v8::Object> biv = info[2].As<v8::Object>();

  uint8_t *data = (uint8_t *)node::Buffer::Data(bdata);
  size_t dlen = node::Buffer::Length(bdata);

  const uint8_t *key = (uint8_t *)node::Buffer::Data(bkey);
  size_t klen = node::Buffer::Length(bkey);

  const uint8_t *iv = (uint8_t *)node::Buffer::Data(biv);
  size_t ilen = node::Buffer::Length(biv);

  if (klen != 32)
    return Nan::ThrowError("Bad key size.");

  if (ilen != 16)
    return Nan::ThrowError("Bad IV size.");

  uint32_t olen = BCRYPTO_ENCIPHER_SIZE(dlen);
  uint8_t *out = (uint8_t *)malloc(olen);

  if (out == NULL)
    return Nan::ThrowError("Could not allocate ciphertext.");

  if (!bcrypto_encipher(data, dlen, key, iv, out, &olen))
    return Nan::ThrowError("Encipher failed.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, olen).ToLocalChecked());
}

NAN_METHOD(decipher) {
  if (info.Length() < 3)
    return Nan::ThrowError("decipher() requires arguments.");

  if (!node::Buffer::HasInstance(info[0]))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(info[1]))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  if (!node::Buffer::HasInstance(info[2]))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  v8::Local<v8::Object> bdata = info[0].As<v8::Object>();
  v8::Local<v8::Object> bkey = info[1].As<v8::Object>();
  v8::Local<v8::Object> biv = info[2].As<v8::Object>();

  uint8_t *data = (uint8_t *)node::Buffer::Data(bdata);
  size_t dlen = node::Buffer::Length(bdata);

  const uint8_t *key = (uint8_t *)node::Buffer::Data(bkey);
  size_t klen = node::Buffer::Length(bkey);

  const uint8_t *iv = (uint8_t *)node::Buffer::Data(biv);
  size_t ilen = node::Buffer::Length(biv);

  if (klen != 32)
    return Nan::ThrowError("Bad key size.");

  if (ilen != 16)
    return Nan::ThrowError("Bad IV size.");

  uint32_t olen = BCRYPTO_DECIPHER_SIZE(dlen);
  uint8_t *out = (uint8_t *)malloc(olen);

  if (out == NULL)
    return Nan::ThrowError("Could not allocate plaintext.");

  if (!bcrypto_decipher(data, dlen, key, iv, out, &olen))
    return Nan::ThrowError("Decipher failed.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, olen).ToLocalChecked());
}

NAN_METHOD(random_bytes) {
  if (info.Length() < 1)
    return Nan::ThrowError("random_bytes() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  const uint32_t outlen = info[0]->Uint32Value();

  if (outlen & 0x80000000)
    return Nan::ThrowError("Size too large.");

  uint8_t *out = (uint8_t *)malloc(outlen);

  if (out == NULL)
    return Nan::ThrowError("Could not allocate random bytes.");

  for (;;) {
    int status = RAND_status();

    assert(status >= 0);

    if (status != 0)
      break;

    if (RAND_poll() == 0)
      break;
  }

  const int r = RAND_bytes(out, outlen);

  if (r == 0)
    return Nan::ThrowError("Could not get random bytes.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, outlen).ToLocalChecked());
}

NAN_MODULE_INIT(init) {
  Nan::Export(target, "pbkdf2", pbkdf2);
  Nan::Export(target, "pbkdf2Async", pbkdf2_async);
  Nan::Export(target, "scrypt", scrypt);
  Nan::Export(target, "scryptAsync", scrypt_async);
  Nan::Export(target, "cleanse", cleanse);
  Nan::Export(target, "encipher", encipher);
  Nan::Export(target, "decipher", decipher);
  Nan::Export(target, "randomBytes", random_bytes);

  RIPEMD160::Init(target);
  SHA1::Init(target);
  SHA256::Init(target);
  SHA512::Init(target);
  Hash160::Init(target);
  Hash256::Init(target);
  Keccak::Init(target);
  Blake2b::Init(target);

  ChaCha20::Init(target);
  Poly1305::Init(target);
}

NODE_MODULE(bcrypto, init)
