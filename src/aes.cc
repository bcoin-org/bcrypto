#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "aes/aes.h"
#include "aes.h"

static Nan::Persistent<v8::FunctionTemplate> aes_constructor;

BAES::BAES() {}

BAES::~BAES() {}

void
BAES::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BAES::New);

  aes_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("AES").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetMethod(tpl, "encipher", BAES::Encipher);
  Nan::SetMethod(tpl, "decipher", BAES::Decipher);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(aes_constructor);

  target->Set(Nan::New("aes").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BAES::New) {
  return Nan::ThrowError("Could not create AES instance.");
}

NAN_METHOD(BAES::Encipher) {
  if (info.Length() < 3)
    return Nan::ThrowError("aes.encipher() requires arguments.");

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

  uint32_t olen = BCRYPTO_AES_ENCIPHER_SIZE(dlen);
  uint8_t *out = (uint8_t *)malloc(olen);

  if (out == NULL)
    return Nan::ThrowError("Could not allocate ciphertext.");

  if (!bcrypto_aes_encipher(data, dlen, key, iv, out, &olen)) {
    free(out);
    return Nan::ThrowError("Encipher failed.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, olen).ToLocalChecked());
}

NAN_METHOD(BAES::Decipher) {
  if (info.Length() < 3)
    return Nan::ThrowError("aes.decipher() requires arguments.");

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

  uint32_t olen = BCRYPTO_AES_DECIPHER_SIZE(dlen);
  uint8_t *out = (uint8_t *)malloc(olen);

  if (out == NULL)
    return Nan::ThrowError("Could not allocate plaintext.");

  if (!bcrypto_aes_decipher(data, dlen, key, iv, out, &olen)) {
    free(out);
    return Nan::ThrowError("Decipher failed.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, olen).ToLocalChecked());
}
