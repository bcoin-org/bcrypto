#include "sha512.h"

static Nan::Persistent<v8::FunctionTemplate> sha512_constructor;

SHA512::SHA512() {
  memset(&ctx, 0, sizeof(SHA512_CTX));
}

SHA512::~SHA512() {}

void
SHA512::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(SHA512::New);

  sha512_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("SHA512").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", SHA512::Init);
  Nan::SetPrototypeMethod(tpl, "update", SHA512::Update);
  Nan::SetPrototypeMethod(tpl, "final", SHA512::Final);
  Nan::SetMethod(tpl, "digest", SHA512::Digest);
  Nan::SetMethod(tpl, "root", SHA512::Root);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(sha512_constructor);

  target->Set(Nan::New("SHA512").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(SHA512::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create SHA512 instance.");

  SHA512 *sha = new SHA512();
  sha->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(SHA512::Init) {
  SHA512 *sha = ObjectWrap::Unwrap<SHA512>(info.Holder());

  SHA512_Init(&sha->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(SHA512::Update) {
  SHA512 *sha = ObjectWrap::Unwrap<SHA512>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("sha512.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA512_Update(&sha->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(SHA512::Final) {
  SHA512 *sha = ObjectWrap::Unwrap<SHA512>(info.Holder());

  uint8_t out[64];

  SHA512_Final(out, &sha->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 64).ToLocalChecked());
}

NAN_METHOD(SHA512::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("sha512.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  uint8_t out[64];

  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, in, inlen);
  SHA512_Final(out, &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 64).ToLocalChecked());
}

NAN_METHOD(SHA512::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha512.root() requires arguments.");

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

  if (leftlen != 64 || rightlen != 64)
    return Nan::ThrowTypeError("Bad node sizes.");

  uint8_t out[64];

  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, left, leftlen);
  SHA512_Update(&ctx, right, rightlen);
  SHA512_Final(out, &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 64).ToLocalChecked());
}
