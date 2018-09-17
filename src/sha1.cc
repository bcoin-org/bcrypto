#include "common.h"
#include "sha1.h"

static SHA_CTX global_ctx;
static uint8_t global_out[20];

static Nan::Persistent<v8::FunctionTemplate> sha1_constructor;

BSHA1::BSHA1() {
  memset(&ctx, 0, sizeof(SHA_CTX));
}

BSHA1::~BSHA1() {}

void
BSHA1::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BSHA1::New);

  sha1_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("SHA1").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BSHA1::Init);
  Nan::SetPrototypeMethod(tpl, "update", BSHA1::Update);
  Nan::SetPrototypeMethod(tpl, "final", BSHA1::Final);
  Nan::SetMethod(tpl, "digest", BSHA1::Digest);
  Nan::SetMethod(tpl, "root", BSHA1::Root);
  Nan::SetMethod(tpl, "multi", BSHA1::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(sha1_constructor);

  target->Set(Nan::New("SHA1").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BSHA1::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create BSHA1 instance.");

  BSHA1 *sha = new BSHA1();
  sha->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA1::Init) {
  BSHA1 *sha = ObjectWrap::Unwrap<BSHA1>(info.Holder());

  SHA1_Init(&sha->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA1::Update) {
  BSHA1 *sha = ObjectWrap::Unwrap<BSHA1>(info.Holder());

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

NAN_METHOD(BSHA1::Final) {
  BSHA1 *sha = ObjectWrap::Unwrap<BSHA1>(info.Holder());

  SHA1_Final(global_out, &sha->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 20).ToLocalChecked());
}

NAN_METHOD(BSHA1::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("sha1.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA1_Init(&global_ctx);
  SHA1_Update(&global_ctx, in, inlen);
  SHA1_Final(global_out, &global_ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 20).ToLocalChecked());
}

NAN_METHOD(BSHA1::Root) {
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

  SHA1_Init(&global_ctx);
  SHA1_Update(&global_ctx, left, leftlen);
  SHA1_Update(&global_ctx, right, rightlen);
  SHA1_Final(global_out, &global_ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 20).ToLocalChecked());
}

NAN_METHOD(BSHA1::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha1.multi() requires arguments.");

  v8::Local<v8::Object> xbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(xbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(ybuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *x = (uint8_t *)node::Buffer::Data(xbuf);
  const uint8_t *y = (uint8_t *)node::Buffer::Data(ybuf);

  size_t xlen = node::Buffer::Length(xbuf);
  size_t ylen = node::Buffer::Length(ybuf);

  const uint8_t *z = NULL;
  size_t zlen = 0;

  if (info.Length() > 2 && !IsNull(info[2])) {
    v8::Local<v8::Object> zbuf = info[2].As<v8::Object>();

    if (!node::Buffer::HasInstance(zbuf))
      return Nan::ThrowTypeError("Third argument must be a buffer.");

    z = (const uint8_t *)node::Buffer::Data(zbuf);
    zlen = node::Buffer::Length(zbuf);
  }

  SHA1_Init(&global_ctx);
  SHA1_Update(&global_ctx, x, xlen);
  SHA1_Update(&global_ctx, y, ylen);
  if (z)
    SHA1_Update(&global_ctx, z, zlen);
  SHA1_Final(global_out, &global_ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 20).ToLocalChecked());
}
