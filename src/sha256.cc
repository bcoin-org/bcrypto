#include "sha256.h"

static Nan::Persistent<v8::FunctionTemplate> sha256_constructor;

SHA256::SHA256() {
  memset(&ctx, 0, sizeof(SHA256_CTX));
}

SHA256::~SHA256() {}

void
SHA256::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(SHA256::New);

  sha256_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("SHA256").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", SHA256::Init);
  Nan::SetPrototypeMethod(tpl, "update", SHA256::Update);
  Nan::SetPrototypeMethod(tpl, "final", SHA256::Final);
  Nan::SetMethod(tpl, "digest", SHA256::Digest);
  Nan::SetMethod(tpl, "root", SHA256::Root);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(sha256_constructor);

  target->Set(Nan::New("SHA256").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(SHA256::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create SHA256 instance.");

  SHA256 *sha = new SHA256();
  sha->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(SHA256::Init) {
  SHA256 *sha = ObjectWrap::Unwrap<SHA256>(info.Holder());

  SHA256_Init(&sha->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(SHA256::Update) {
  SHA256 *sha = ObjectWrap::Unwrap<SHA256>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("sha256.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA256_Update(&sha->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(SHA256::Final) {
  SHA256 *sha = ObjectWrap::Unwrap<SHA256>(info.Holder());

  uint8_t out[32];

  SHA256_Final(out, &sha->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(SHA256::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("sha256.digest() requires arguments.");

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

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(SHA256::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha256.root() requires arguments.");

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

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}
