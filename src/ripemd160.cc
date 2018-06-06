#include "ripemd160.h"

static RIPEMD160_CTX global_ctx;
static uint8_t global_out[20];

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj);

static Nan::Persistent<v8::FunctionTemplate> ripemd160_constructor;

RIPEMD160::RIPEMD160() {
  memset(&ctx, 0, sizeof(RIPEMD160_CTX));
}

RIPEMD160::~RIPEMD160() {}

void
RIPEMD160::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(RIPEMD160::New);

  ripemd160_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("RIPEMD160").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", RIPEMD160::Init);
  Nan::SetPrototypeMethod(tpl, "update", RIPEMD160::Update);
  Nan::SetPrototypeMethod(tpl, "final", RIPEMD160::Final);
  Nan::SetMethod(tpl, "digest", RIPEMD160::Digest);
  Nan::SetMethod(tpl, "root", RIPEMD160::Root);
  Nan::SetMethod(tpl, "multi", RIPEMD160::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(ripemd160_constructor);

  target->Set(Nan::New("RIPEMD160").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(RIPEMD160::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create RIPEMD160 instance.");

  RIPEMD160 *rmd = new RIPEMD160();
  rmd->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(RIPEMD160::Init) {
  RIPEMD160 *rmd = ObjectWrap::Unwrap<RIPEMD160>(info.Holder());

  RIPEMD160_Init(&rmd->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(RIPEMD160::Update) {
  RIPEMD160 *rmd = ObjectWrap::Unwrap<RIPEMD160>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ripemd160.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  RIPEMD160_Update(&rmd->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(RIPEMD160::Final) {
  RIPEMD160 *rmd = ObjectWrap::Unwrap<RIPEMD160>(info.Holder());

  RIPEMD160_Final(global_out, &rmd->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 20).ToLocalChecked());
}

NAN_METHOD(RIPEMD160::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("ripemd160.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  RIPEMD160_Init(&global_ctx);
  RIPEMD160_Update(&global_ctx, in, inlen);
  RIPEMD160_Final(global_out, &global_ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 20).ToLocalChecked());
}

NAN_METHOD(RIPEMD160::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("ripemd160.root() requires arguments.");

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

  RIPEMD160_Init(&global_ctx);
  RIPEMD160_Update(&global_ctx, left, leftlen);
  RIPEMD160_Update(&global_ctx, right, rightlen);
  RIPEMD160_Final(global_out, &global_ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 20).ToLocalChecked());
}

NAN_METHOD(RIPEMD160::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("ripemd160.multi() requires arguments.");

  v8::Local<v8::Object> onebuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> twobuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(onebuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(twobuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *one = (uint8_t *)node::Buffer::Data(onebuf);
  const uint8_t *two = (uint8_t *)node::Buffer::Data(twobuf);

  size_t onelen = node::Buffer::Length(onebuf);
  size_t twolen = node::Buffer::Length(twobuf);

  uint8_t *three = NULL;
  size_t threelen = 0;

  if (info.Length() > 2 && !IsNull(info[2])) {
    v8::Local<v8::Object> threebuf = info[2].As<v8::Object>();

    if (!node::Buffer::HasInstance(threebuf))
      return Nan::ThrowTypeError("Third argument must be a buffer.");

    three = (uint8_t *)node::Buffer::Data(threebuf);
    threelen = node::Buffer::Length(threebuf);
  }

  RIPEMD160_Init(&global_ctx);
  RIPEMD160_Update(&global_ctx, one, onelen);
  RIPEMD160_Update(&global_ctx, two, twolen);
  if (three)
    RIPEMD160_Update(&global_ctx, three, threelen);
  RIPEMD160_Final(global_out, &global_ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 20).ToLocalChecked());
}

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;
  return obj->IsNull() || obj->IsUndefined();
}
