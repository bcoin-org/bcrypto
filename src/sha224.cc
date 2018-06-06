#include "sha224.h"

static SHA256_CTX global_ctx;
static uint8_t global_out[28];

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj);

static Nan::Persistent<v8::FunctionTemplate> sha224_constructor;

BSHA224::BSHA224() {
  memset(&ctx, 0, sizeof(SHA256_CTX));
}

BSHA224::~BSHA224() {}

void
BSHA224::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BSHA224::New);

  sha224_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("SHA224").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BSHA224::Init);
  Nan::SetPrototypeMethod(tpl, "update", BSHA224::Update);
  Nan::SetPrototypeMethod(tpl, "final", BSHA224::Final);
  Nan::SetMethod(tpl, "digest", BSHA224::Digest);
  Nan::SetMethod(tpl, "root", BSHA224::Root);
  Nan::SetMethod(tpl, "multi", BSHA224::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(sha224_constructor);

  target->Set(Nan::New("SHA224").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BSHA224::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create SHA224 instance.");

  BSHA224 *sha = new BSHA224();
  sha->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA224::Init) {
  BSHA224 *sha = ObjectWrap::Unwrap<BSHA224>(info.Holder());

  SHA224_Init(&sha->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA224::Update) {
  BSHA224 *sha = ObjectWrap::Unwrap<BSHA224>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("sha224.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA224_Update(&sha->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA224::Final) {
  BSHA224 *sha = ObjectWrap::Unwrap<BSHA224>(info.Holder());

  SHA224_Final(global_out, &sha->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 28).ToLocalChecked());
}

NAN_METHOD(BSHA224::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("sha224.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA224_Init(&global_ctx);
  SHA224_Update(&global_ctx, in, inlen);
  SHA224_Final(global_out, &global_ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 28).ToLocalChecked());
}

NAN_METHOD(BSHA224::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha224.root() requires arguments.");

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

  if (leftlen != 28 || rightlen != 28)
    return Nan::ThrowTypeError("Bad node sizes.");

  SHA224_Init(&global_ctx);
  SHA224_Update(&global_ctx, left, leftlen);
  SHA224_Update(&global_ctx, right, rightlen);
  SHA224_Final(global_out, &global_ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 28).ToLocalChecked());
}

NAN_METHOD(BSHA224::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha224.multi() requires arguments.");

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

  SHA224_Init(&global_ctx);
  SHA224_Update(&global_ctx, one, onelen);
  SHA224_Update(&global_ctx, two, twolen);
  if (three)
    SHA224_Update(&global_ctx, three, threelen);
  SHA224_Final(global_out, &global_ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 28).ToLocalChecked());
}

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;
  return obj->IsNull() || obj->IsUndefined();
}
