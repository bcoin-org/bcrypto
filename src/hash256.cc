#include "hash256.h"

static Nan::Persistent<v8::FunctionTemplate> hash256_constructor;

Hash256::Hash256() {
  memset(&ctx, 0, sizeof(SHA256_CTX));
}

Hash256::~Hash256() {}

void
Hash256::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(Hash256::New);

  hash256_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Hash256").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", Hash256::Init);
  Nan::SetPrototypeMethod(tpl, "update", Hash256::Update);
  Nan::SetPrototypeMethod(tpl, "final", Hash256::Final);
  Nan::SetMethod(tpl, "digest", Hash256::Digest);
  Nan::SetMethod(tpl, "root", Hash256::Root);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(hash256_constructor);

  target->Set(Nan::New("Hash256").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(Hash256::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Hash256 instance.");

  Hash256 *hash = new Hash256();
  hash->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Hash256::Init) {
  Hash256 *hash = ObjectWrap::Unwrap<Hash256>(info.Holder());

  SHA256_Init(&hash->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Hash256::Update) {
  Hash256 *hash = ObjectWrap::Unwrap<Hash256>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("hash256.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA256_Update(&hash->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Hash256::Final) {
  Hash256 *hash = ObjectWrap::Unwrap<Hash256>(info.Holder());

  uint8_t out[32];

  SHA256_Final(out, &hash->ctx);
  SHA256_Init(&hash->ctx);
  SHA256_Update(&hash->ctx, out, 32);
  SHA256_Final(out, &hash->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(Hash256::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("hash256.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  uint8_t out[32];

  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, in, inlen);
  SHA256_Final(out, &ctx);
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, out, 32);
  SHA256_Final(out, &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(Hash256::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("hash256.root() requires arguments.");

  v8::Local<v8::Object> lbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> rbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(lbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *left = (uint8_t *)node::Buffer::Data(lbuf);
  const uint8_t *right = (uint8_t *)node::Buffer::Data(rbuf);

  size_t leftlen = node::Buffer::Length(lbuf);
  size_t rightlen = node::Buffer::Length(rbuf);

  if (leftlen != 32 || rightlen != 32)
    return Nan::ThrowTypeError("Bad node sizes.");

  uint8_t out[32];

  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, left, leftlen);
  SHA256_Update(&ctx, right, rightlen);
  SHA256_Final(out, &ctx);
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, out, 32);
  SHA256_Final(out, &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}
