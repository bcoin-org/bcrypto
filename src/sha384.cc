#include "sha384.h"

static SHA512_CTX global_ctx;
static uint8_t global_out[48];

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj);

static Nan::Persistent<v8::FunctionTemplate> sha384_constructor;

BSHA384::BSHA384() {
  memset(&ctx, 0, sizeof(SHA512_CTX));
}

BSHA384::~BSHA384() {}

void
BSHA384::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BSHA384::New);

  sha384_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("SHA384").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BSHA384::Init);
  Nan::SetPrototypeMethod(tpl, "update", BSHA384::Update);
  Nan::SetPrototypeMethod(tpl, "final", BSHA384::Final);
  Nan::SetMethod(tpl, "digest", BSHA384::Digest);
  Nan::SetMethod(tpl, "root", BSHA384::Root);
  Nan::SetMethod(tpl, "multi", BSHA384::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(sha384_constructor);

  target->Set(Nan::New("SHA384").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BSHA384::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create SHA384 instance.");

  BSHA384 *sha = new BSHA384();
  sha->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA384::Init) {
  BSHA384 *sha = ObjectWrap::Unwrap<BSHA384>(info.Holder());

  SHA384_Init(&sha->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA384::Update) {
  BSHA384 *sha = ObjectWrap::Unwrap<BSHA384>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("sha384.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA384_Update(&sha->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA384::Final) {
  BSHA384 *sha = ObjectWrap::Unwrap<BSHA384>(info.Holder());

  SHA384_Final(global_out, &sha->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 48).ToLocalChecked());
}

NAN_METHOD(BSHA384::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("sha384.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA384_Init(&global_ctx);
  SHA384_Update(&global_ctx, in, inlen);
  SHA384_Final(global_out, &global_ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 48).ToLocalChecked());
}

NAN_METHOD(BSHA384::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha384.root() requires arguments.");

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

  if (leftlen != 48 || rightlen != 48)
    return Nan::ThrowTypeError("Bad node sizes.");

  SHA384_Init(&global_ctx);
  SHA384_Update(&global_ctx, left, leftlen);
  SHA384_Update(&global_ctx, right, rightlen);
  SHA384_Final(global_out, &global_ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 48).ToLocalChecked());
}

NAN_METHOD(BSHA384::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha384.multi() requires arguments.");

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

  SHA384_Init(&global_ctx);
  SHA384_Update(&global_ctx, one, onelen);
  SHA384_Update(&global_ctx, two, twolen);
  if (three)
    SHA384_Update(&global_ctx, three, threelen);
  SHA384_Final(global_out, &global_ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 48).ToLocalChecked());
}

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;
  return obj->IsNull() || obj->IsUndefined();
}
