#include "blake2b.h"

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj);

static Nan::Persistent<v8::FunctionTemplate> blake2b_constructor;

Blake2b::Blake2b() {
  memset(&ctx, 0, sizeof(blake2b_ctx));
}

Blake2b::~Blake2b() {}

void
Blake2b::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(Blake2b::New);

  blake2b_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Blake2b").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", Blake2b::Init);
  Nan::SetPrototypeMethod(tpl, "update", Blake2b::Update);
  Nan::SetPrototypeMethod(tpl, "final", Blake2b::Final);
  Nan::SetMethod(tpl, "digest", Blake2b::Digest);
  Nan::SetMethod(tpl, "root", Blake2b::Root);
  Nan::SetMethod(tpl, "mac", Blake2b::Mac);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(blake2b_constructor);

  target->Set(Nan::New("Blake2b").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(Blake2b::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Blake2b instance.");

  Blake2b *blake = new Blake2b();
  blake->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Blake2b::Init) {
  Blake2b *blake = ObjectWrap::Unwrap<Blake2b>(info.Holder());

  uint32_t outlen = 32;

  if (info.Length() > 0 && !IsNull(info[0])) {
    if (!info[0]->IsNumber())
      return Nan::ThrowTypeError("First argument must be a number.");

    outlen = info[0]->Uint32Value();

    if (outlen == 0 || outlen > BLAKE2B_OUTBYTES)
      return Nan::ThrowTypeError("First argument must be a number.");
  }

  uint8_t *key = NULL;
  size_t keylen = 0;

  if (info.Length() > 1 && !IsNull(info[1])) {
    v8::Local<v8::Object> buf = info[1].As<v8::Object>();

    if (!node::Buffer::HasInstance(buf))
      return Nan::ThrowTypeError("Second argument must be a buffer.");

    key = (uint8_t *)node::Buffer::Data(buf);
    keylen = node::Buffer::Length(buf);

    if (keylen > BLAKE2B_OUTBYTES)
      return Nan::ThrowTypeError("Bad key size.");
  }

  if (keylen > 0) {
    if (blake2b_init_key(&blake->ctx, outlen, key, keylen) < 0)
      return Nan::ThrowTypeError("Could not allocate context");
  } else {
    if (blake2b_init(&blake->ctx, outlen) < 0)
      return Nan::ThrowTypeError("Could not allocate context");
  }

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Blake2b::Update) {
  Blake2b *blake = ObjectWrap::Unwrap<Blake2b>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("blake2b.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  blake2b_update(&blake->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Blake2b::Final) {
  Blake2b *blake = ObjectWrap::Unwrap<Blake2b>(info.Holder());

  uint8_t out[BLAKE2B_OUTBYTES];
  uint32_t outlen = blake->ctx.outlen;

  blake2b_final(&blake->ctx, out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], outlen).ToLocalChecked());
}

NAN_METHOD(Blake2b::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("blake2b.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  uint32_t outlen = 32;
  uint8_t *key = NULL;
  size_t keylen = 0;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsNumber())
      return Nan::ThrowTypeError("Second argument must be a number.");

    outlen = info[1]->Uint32Value();

    if (outlen == 0 || outlen > BLAKE2B_OUTBYTES)
      return Nan::ThrowTypeError("Second argument must be a number.");
  }

  if (info.Length() > 2 && !IsNull(info[2])) {
    v8::Local<v8::Object> kbuf = info[2].As<v8::Object>();

    if (!node::Buffer::HasInstance(kbuf))
      return Nan::ThrowTypeError("Third argument must be a buffer.");

    key = (uint8_t *)node::Buffer::Data(kbuf);
    keylen = node::Buffer::Length(kbuf);

    if (keylen > BLAKE2B_OUTBYTES)
      return Nan::ThrowTypeError("Third argument must be a number.");
  }

  blake2b_ctx ctx;

  if (keylen > 0) {
    if (blake2b_init_key(&ctx, outlen, key, keylen) < 0)
      return Nan::ThrowTypeError("Could not allocate context.");
  } else {
    if (blake2b_init(&ctx, outlen) < 0)
      return Nan::ThrowTypeError("Could not allocate context.");
  }

  uint8_t out[BLAKE2B_OUTBYTES];

  blake2b_update(&ctx, in, inlen);
  blake2b_final(&ctx, out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], outlen).ToLocalChecked());
}

NAN_METHOD(Blake2b::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("blake2b.root() requires arguments.");

  v8::Local<v8::Object> lbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(lbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *left = (uint8_t *)node::Buffer::Data(lbuf);
  size_t leftlen = node::Buffer::Length(lbuf);

  v8::Local<v8::Object> rbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *right = (uint8_t *)node::Buffer::Data(rbuf);
  size_t rightlen = node::Buffer::Length(rbuf);

  uint32_t outlen = 32;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsNumber())
      return Nan::ThrowTypeError("Third argument must be a number.");

    outlen = info[2]->Uint32Value();
  }

  if (leftlen != outlen || rightlen != outlen)
    return Nan::ThrowTypeError("Bad node sizes.");

  blake2b_ctx ctx;

  if (blake2b_init(&ctx, outlen) < 0)
    return Nan::ThrowTypeError("Could not allocate context.");

  uint8_t out[BLAKE2B_OUTBYTES];

  blake2b_update(&ctx, left, leftlen);
  blake2b_update(&ctx, right, rightlen);
  blake2b_final(&ctx, out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], outlen).ToLocalChecked());
}

NAN_METHOD(Blake2b::Mac) {
  if (info.Length() < 2)
    return Nan::ThrowError("blake2b.mac() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  uint8_t *key = NULL;
  size_t keylen = 0;
  uint32_t outlen = 32;

  v8::Local<v8::Object> kbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  key = (uint8_t *)node::Buffer::Data(kbuf);
  keylen = node::Buffer::Length(kbuf);

  if (keylen > BLAKE2B_OUTBYTES)
    return Nan::ThrowTypeError("Second argument must be a number.");

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsNumber())
      return Nan::ThrowTypeError("Third argument must be a number.");

    outlen = info[2]->Uint32Value();

    if (outlen == 0 || outlen > BLAKE2B_OUTBYTES)
      return Nan::ThrowTypeError("Third argument must be a number.");
  }

  blake2b_ctx ctx;

  if (keylen > 0) {
    if (blake2b_init_key(&ctx, outlen, key, keylen) < 0)
      return Nan::ThrowTypeError("Could not allocate context.");
  } else {
    if (blake2b_init(&ctx, outlen) < 0)
      return Nan::ThrowTypeError("Could not allocate context.");
  }

  uint8_t out[BLAKE2B_OUTBYTES];

  blake2b_update(&ctx, in, inlen);
  blake2b_final(&ctx, out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], outlen).ToLocalChecked());
}

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;
  return obj->IsNull() || obj->IsUndefined();
}
