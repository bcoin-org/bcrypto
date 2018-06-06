#include "md5.h"

static MD5_CTX global_ctx;
static uint8_t global_out[16];

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj);

static Nan::Persistent<v8::FunctionTemplate> md5_constructor;

BMD5::BMD5() {
  memset(&ctx, 0, sizeof(MD5_CTX));
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

  target->Set(Nan::New("MD5").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BMD5::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create BMD5 instance.");

  BMD5 *md5 = new BMD5();
  md5->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BMD5::Init) {
  BMD5 *md5 = ObjectWrap::Unwrap<BMD5>(info.Holder());

  MD5_Init(&md5->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BMD5::Update) {
  BMD5 *md5 = ObjectWrap::Unwrap<BMD5>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("md5.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  MD5_Update(&md5->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BMD5::Final) {
  BMD5 *md5 = ObjectWrap::Unwrap<BMD5>(info.Holder());

  MD5_Final(global_out, &md5->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 16).ToLocalChecked());
}

NAN_METHOD(BMD5::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("md5.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  MD5_Init(&global_ctx);
  MD5_Update(&global_ctx, in, inlen);
  MD5_Final(global_out, &global_ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 16).ToLocalChecked());
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

  const uint8_t *left = (uint8_t *)node::Buffer::Data(lbuf);
  const uint8_t *right = (uint8_t *)node::Buffer::Data(rbuf);

  size_t leftlen = node::Buffer::Length(lbuf);
  size_t rightlen = node::Buffer::Length(rbuf);

  if (leftlen != 16 || rightlen != 16)
    return Nan::ThrowTypeError("Bad node sizes.");

  MD5_Init(&global_ctx);
  MD5_Update(&global_ctx, left, leftlen);
  MD5_Update(&global_ctx, right, rightlen);
  MD5_Final(global_out, &global_ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 16).ToLocalChecked());
}

NAN_METHOD(BMD5::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("md5.multi() requires arguments.");

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

  MD5_Init(&global_ctx);
  MD5_Update(&global_ctx, one, onelen);
  MD5_Update(&global_ctx, two, twolen);
  if (three)
    MD5_Update(&global_ctx, three, threelen);
  MD5_Final(global_out, &global_ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 16).ToLocalChecked());
}

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;
  return obj->IsNull() || obj->IsUndefined();
}
