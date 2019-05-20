#include "common.h"
#include "hash160.h"

static Nan::Persistent<v8::FunctionTemplate> hash160_constructor;

BHash160::BHash160() {
  memset(&ctx, 0, sizeof(struct sha256_ctx));
}

BHash160::~BHash160() {}

void
BHash160::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BHash160::New);

  hash160_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Hash160").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BHash160::Init);
  Nan::SetPrototypeMethod(tpl, "update", BHash160::Update);
  Nan::SetPrototypeMethod(tpl, "final", BHash160::Final);
  Nan::SetMethod(tpl, "digest", BHash160::Digest);
  Nan::SetMethod(tpl, "root", BHash160::Root);
  Nan::SetMethod(tpl, "multi", BHash160::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(hash160_constructor);

  Nan::Set(target, Nan::New("Hash160").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BHash160::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Hash160 instance.");

  BHash160 *hash = new BHash160();
  hash->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHash160::Init) {
  BHash160 *hash = ObjectWrap::Unwrap<BHash160>(info.Holder());

  sha256_init(&hash->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHash160::Update) {
  BHash160 *hash = ObjectWrap::Unwrap<BHash160>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("hash160.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  sha256_update(&hash->ctx, inlen, in);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHash160::Final) {
  BHash160 *hash = ObjectWrap::Unwrap<BHash160>(info.Holder());

  struct ripemd160_ctx rctx;
  uint8_t out[32];

  sha256_digest(&hash->ctx, 32, &out[0]);

  ripemd160_init(&rctx);
  ripemd160_update(&rctx, 32, &out[0]);
  ripemd160_digest(&rctx, 20, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(BHash160::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("hash160.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  struct sha256_ctx sctx;
  struct ripemd160_ctx rctx;
  uint8_t out[32];

  sha256_init(&sctx);
  sha256_update(&sctx, inlen, in);
  sha256_digest(&sctx, 32, &out[0]);

  ripemd160_init(&rctx);
  ripemd160_update(&rctx, 32, &out[0]);
  ripemd160_digest(&rctx, 20, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(BHash160::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("hash160.root() requires arguments.");

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

  if (leftlen != 20 || rightlen != 20)
    return Nan::ThrowRangeError("Invalid node sizes.");

  struct sha256_ctx sctx;
  struct ripemd160_ctx rctx;
  uint8_t out[32];

  sha256_init(&sctx);
  sha256_update(&sctx, leftlen, left);
  sha256_update(&sctx, rightlen, right);
  sha256_digest(&sctx, 32, &out[0]);

  ripemd160_init(&rctx);
  ripemd160_update(&rctx, 32, &out[0]);
  ripemd160_digest(&rctx, 20, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(BHash160::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("hash160.multi() requires arguments.");

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

  struct sha256_ctx sctx;
  struct ripemd160_ctx rctx;
  uint8_t out[32];

  sha256_init(&sctx);
  sha256_update(&sctx, xlen, x);
  sha256_update(&sctx, ylen, y);
  sha256_update(&sctx, zlen, z);
  sha256_digest(&sctx, 32, &out[0]);

  ripemd160_init(&rctx);
  ripemd160_update(&rctx, 32, &out[0]);
  ripemd160_digest(&rctx, 20, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}
