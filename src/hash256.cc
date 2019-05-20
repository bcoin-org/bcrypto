#include "common.h"
#include "hash256.h"

static Nan::Persistent<v8::FunctionTemplate> hash256_constructor;

BHash256::BHash256() {
  memset(&ctx, 0, sizeof(struct sha256_ctx));
}

BHash256::~BHash256() {}

void
BHash256::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BHash256::New);

  hash256_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Hash256").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BHash256::Init);
  Nan::SetPrototypeMethod(tpl, "update", BHash256::Update);
  Nan::SetPrototypeMethod(tpl, "final", BHash256::Final);
  Nan::SetMethod(tpl, "digest", BHash256::Digest);
  Nan::SetMethod(tpl, "root", BHash256::Root);
  Nan::SetMethod(tpl, "multi", BHash256::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(hash256_constructor);

  Nan::Set(target, Nan::New("Hash256").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BHash256::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Hash256 instance.");

  BHash256 *hash = new BHash256();
  hash->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHash256::Init) {
  BHash256 *hash = ObjectWrap::Unwrap<BHash256>(info.Holder());

  sha256_init(&hash->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHash256::Update) {
  BHash256 *hash = ObjectWrap::Unwrap<BHash256>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("hash256.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  sha256_update(&hash->ctx, inlen, in);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHash256::Final) {
  BHash256 *hash = ObjectWrap::Unwrap<BHash256>(info.Holder());

  uint8_t out[32];

  sha256_digest(&hash->ctx, 32, &out[0]);

  sha256_init(&hash->ctx);
  sha256_update(&hash->ctx, 32, &out[0]);
  sha256_digest(&hash->ctx, 32, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BHash256::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("hash256.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  struct sha256_ctx ctx;
  uint8_t out[32];

  sha256_init(&ctx);
  sha256_update(&ctx, inlen, in);
  sha256_digest(&ctx, 32, &out[0]);

  sha256_init(&ctx);
  sha256_update(&ctx, 32, &out[0]);
  sha256_digest(&ctx, 32, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BHash256::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("hash256.root() requires arguments.");

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

  if (leftlen != 32 || rightlen != 32)
    return Nan::ThrowRangeError("Invalid node sizes.");

  struct sha256_ctx ctx;
  uint8_t out[32];

  sha256_init(&ctx);
  sha256_update(&ctx, leftlen, left);
  sha256_update(&ctx, rightlen, right);
  sha256_digest(&ctx, 32, &out[0]);

  sha256_init(&ctx);
  sha256_update(&ctx, 32, &out[0]);
  sha256_digest(&ctx, 32, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BHash256::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("hash256.multi() requires arguments.");

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

  struct sha256_ctx ctx;
  uint8_t out[32];

  sha256_init(&ctx);
  sha256_update(&ctx, xlen, x);
  sha256_update(&ctx, ylen, y);
  sha256_update(&ctx, zlen, z);
  sha256_digest(&ctx, 32, &out[0]);

  sha256_init(&ctx);
  sha256_update(&ctx, 32, &out[0]);
  sha256_digest(&ctx, 32, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}
