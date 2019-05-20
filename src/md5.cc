#include "common.h"
#include "md5.h"

static Nan::Persistent<v8::FunctionTemplate> md5_constructor;

BMD5::BMD5() {
  memset(&ctx, 0, sizeof(struct md5_ctx));
}

BMD5::~BMD5() {}

void
BMD5::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BMD5::New);

  md5_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("MD5").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BMD5::Init);
  Nan::SetPrototypeMethod(tpl, "update", BMD5::Update);
  Nan::SetPrototypeMethod(tpl, "final", BMD5::Final);
  Nan::SetMethod(tpl, "digest", BMD5::Digest);
  Nan::SetMethod(tpl, "root", BMD5::Root);
  Nan::SetMethod(tpl, "multi", BMD5::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(md5_constructor);

  Nan::Set(target, Nan::New("MD5").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BMD5::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create MD5 instance.");

  BMD5 *md5 = new BMD5();
  md5->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BMD5::Init) {
  BMD5 *md5 = ObjectWrap::Unwrap<BMD5>(info.Holder());

  md5_init(&md5->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BMD5::Update) {
  BMD5 *md5 = ObjectWrap::Unwrap<BMD5>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("md5.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  md5_update(&md5->ctx, inlen, in);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BMD5::Final) {
  BMD5 *md5 = ObjectWrap::Unwrap<BMD5>(info.Holder());

  uint8_t out[16];

  md5_digest(&md5->ctx, 16, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 16).ToLocalChecked());
}

NAN_METHOD(BMD5::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("md5.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  struct md5_ctx ctx;
  uint8_t out[16];

  md5_init(&ctx);
  md5_update(&ctx, inlen, in);
  md5_digest(&ctx, 16, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 16).ToLocalChecked());
}

NAN_METHOD(BMD5::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("md5.root() requires arguments.");

  v8::Local<v8::Object> lbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> rbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(lbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *left = (const uint8_t *)node::Buffer::Data(lbuf);
  const uint8_t *right = (const uint8_t *)node::Buffer::Data(rbuf);

  size_t leftlen = node::Buffer::Length(lbuf);
  size_t rightlen = node::Buffer::Length(rbuf);

  if (leftlen != 16 || rightlen != 16)
    return Nan::ThrowRangeError("Invalid node sizes.");

  struct md5_ctx ctx;
  uint8_t out[16];

  md5_init(&ctx);
  md5_update(&ctx, leftlen, left);
  md5_update(&ctx, rightlen, right);
  md5_digest(&ctx, 16, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 16).ToLocalChecked());
}

NAN_METHOD(BMD5::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("md5.multi() requires arguments.");

  v8::Local<v8::Object> xbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(xbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(ybuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *x = (const uint8_t *)node::Buffer::Data(xbuf);
  const uint8_t *y = (const uint8_t *)node::Buffer::Data(ybuf);

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

  struct md5_ctx ctx;
  uint8_t out[16];

  md5_init(&ctx);
  md5_update(&ctx, xlen, x);
  md5_update(&ctx, ylen, y);
  md5_update(&ctx, zlen, z);
  md5_digest(&ctx, 16, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 16).ToLocalChecked());
}
