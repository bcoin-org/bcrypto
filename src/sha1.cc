#include "sha1.h"

static Nan::Persistent<v8::FunctionTemplate> sha1_constructor;

SHA1::SHA1() {
  memset(&ctx, 0, sizeof(SHA_CTX));
}

SHA1::~SHA1() {}

void
SHA1::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(SHA1::New);

  sha1_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("SHA1").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", SHA1::Init);
  Nan::SetPrototypeMethod(tpl, "update", SHA1::Update);
  Nan::SetPrototypeMethod(tpl, "final", SHA1::Final);
  Nan::SetMethod(tpl, "digest", SHA1::Digest);
  Nan::SetMethod(tpl, "root", SHA1::Root);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(sha1_constructor);

  target->Set(Nan::New("SHA1").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(SHA1::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create SHA1 instance.");

  SHA1 *sha = new SHA1();
  sha->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(SHA1::Init) {
  SHA1 *sha = ObjectWrap::Unwrap<SHA1>(info.Holder());

  SHA1_Init(&sha->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(SHA1::Update) {
  SHA1 *sha = ObjectWrap::Unwrap<SHA1>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("sha1.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA1_Update(&sha->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(SHA1::Final) {
  SHA1 *sha = ObjectWrap::Unwrap<SHA1>(info.Holder());

  uint8_t out[20];

  SHA1_Final(out, &sha->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(SHA1::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("sha1.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  uint8_t out[20];

  SHA_CTX ctx;
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, in, inlen);
  SHA1_Final(out, &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(SHA1::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha1.root() requires arguments.");

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

  if (leftlen != 20 || rightlen != 20)
    return Nan::ThrowTypeError("Bad node sizes.");

  uint8_t out[20];

  SHA_CTX ctx;
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, left, leftlen);
  SHA1_Update(&ctx, right, rightlen);
  SHA1_Final(out, &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}
