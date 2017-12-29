#include "hash160.h"
#include "openssl/ripemd.h"

static Nan::Persistent<v8::FunctionTemplate> hash160_constructor;

Hash160::Hash160() {
  memset(&ctx, 0, sizeof(SHA256_CTX));
}

Hash160::~Hash160() {}

void
Hash160::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(Hash160::New);

  hash160_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Hash160").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", Hash160::Init);
  Nan::SetPrototypeMethod(tpl, "update", Hash160::Update);
  Nan::SetPrototypeMethod(tpl, "final", Hash160::Final);
  Nan::SetMethod(tpl, "digest", Hash160::Digest);
  Nan::SetMethod(tpl, "root", Hash160::Root);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(hash160_constructor);

  target->Set(Nan::New("Hash160").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(Hash160::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Hash160 instance.");

  Hash160 *hash = new Hash160();
  hash->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Hash160::Init) {
  Hash160 *hash = ObjectWrap::Unwrap<Hash160>(info.Holder());

  SHA256_Init(&hash->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Hash160::Update) {
  Hash160 *hash = ObjectWrap::Unwrap<Hash160>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("hash160.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA256_Update(&hash->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Hash160::Final) {
  Hash160 *hash = ObjectWrap::Unwrap<Hash160>(info.Holder());

  uint8_t out[32];

  SHA256_Final(out, &hash->ctx);

  RIPEMD160_CTX ctx;
  RIPEMD160_Init(&ctx);
  RIPEMD160_Update(&ctx, out, 32);
  RIPEMD160_Final(out, &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(Hash160::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("hash160.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  uint8_t out[32];

  SHA256_CTX sctx;
  SHA256_Init(&sctx);
  SHA256_Update(&sctx, in, inlen);
  SHA256_Final(out, &sctx);

  RIPEMD160_CTX rctx;
  RIPEMD160_Init(&rctx);
  RIPEMD160_Update(&rctx, out, 32);
  RIPEMD160_Final(out, &rctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(Hash160::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("hash160.root() requires arguments.");

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

  SHA256_CTX sctx;
  SHA256_Init(&sctx);
  SHA256_Update(&sctx, left, leftlen);
  SHA256_Update(&sctx, right, rightlen);
  SHA256_Final(out, &sctx);

  RIPEMD160_CTX rctx;
  RIPEMD160_Init(&rctx);
  RIPEMD160_Update(&rctx, out, 32);
  RIPEMD160_Final(out, &rctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}
