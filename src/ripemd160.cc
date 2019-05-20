#include "common.h"
#include "ripemd160.h"

static Nan::Persistent<v8::FunctionTemplate> ripemd160_constructor;

BRIPEMD160::BRIPEMD160() {
  memset(&ctx, 0, sizeof(struct ripemd160_ctx));
}

BRIPEMD160::~BRIPEMD160() {}

void
BRIPEMD160::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BRIPEMD160::New);

  ripemd160_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("RIPEMD160").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BRIPEMD160::Init);
  Nan::SetPrototypeMethod(tpl, "update", BRIPEMD160::Update);
  Nan::SetPrototypeMethod(tpl, "final", BRIPEMD160::Final);
  Nan::SetMethod(tpl, "digest", BRIPEMD160::Digest);
  Nan::SetMethod(tpl, "root", BRIPEMD160::Root);
  Nan::SetMethod(tpl, "multi", BRIPEMD160::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(ripemd160_constructor);

  Nan::Set(target, Nan::New("RIPEMD160").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BRIPEMD160::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create RIPEMD160 instance.");

  BRIPEMD160 *rmd = new BRIPEMD160();
  rmd->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BRIPEMD160::Init) {
  BRIPEMD160 *rmd = ObjectWrap::Unwrap<BRIPEMD160>(info.Holder());

  ripemd160_init(&rmd->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BRIPEMD160::Update) {
  BRIPEMD160 *rmd = ObjectWrap::Unwrap<BRIPEMD160>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ripemd160.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  ripemd160_update(&rmd->ctx, inlen, in);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BRIPEMD160::Final) {
  BRIPEMD160 *rmd = ObjectWrap::Unwrap<BRIPEMD160>(info.Holder());

  uint8_t out[20];

  ripemd160_digest(&rmd->ctx, 20, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(BRIPEMD160::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("ripemd160.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  struct ripemd160_ctx ctx;
  uint8_t out[20];

  ripemd160_init(&ctx);
  ripemd160_update(&ctx, inlen, in);
  ripemd160_digest(&ctx, 20, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(BRIPEMD160::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("ripemd160.root() requires arguments.");

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

  struct ripemd160_ctx ctx;
  uint8_t out[20];

  ripemd160_init(&ctx);
  ripemd160_update(&ctx, leftlen, left);
  ripemd160_update(&ctx, rightlen, right);
  ripemd160_digest(&ctx, 20, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(BRIPEMD160::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("ripemd160.multi() requires arguments.");

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

  struct ripemd160_ctx ctx;
  uint8_t out[20];

  ripemd160_init(&ctx);
  ripemd160_update(&ctx, xlen, x);
  ripemd160_update(&ctx, ylen, y);
  ripemd160_update(&ctx, zlen, z);
  ripemd160_digest(&ctx, 20, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}
