#include "blake2b.h"

static bcrypto_blake2b_ctx global_ctx;
static uint8_t global_out[BCRYPTO_BLAKE2B_OUTBYTES];

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj);

static Nan::Persistent<v8::FunctionTemplate> blake2b_constructor;

BBlake2b::BBlake2b() {
  memset(&ctx, 0, sizeof(bcrypto_blake2b_ctx));
}

BBlake2b::~BBlake2b() {}

void
BBlake2b::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BBlake2b::New);

  blake2b_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Blake2b").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BBlake2b::Init);
  Nan::SetPrototypeMethod(tpl, "update", BBlake2b::Update);
  Nan::SetPrototypeMethod(tpl, "final", BBlake2b::Final);
  Nan::SetMethod(tpl, "digest", BBlake2b::Digest);
  Nan::SetMethod(tpl, "root", BBlake2b::Root);
  Nan::SetMethod(tpl, "multi", BBlake2b::Multi);
  Nan::SetMethod(tpl, "mac", BBlake2b::Mac);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(blake2b_constructor);

  target->Set(Nan::New("Blake2b").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BBlake2b::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create BBlake2b instance.");

  BBlake2b *blake = new BBlake2b();
  blake->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BBlake2b::Init) {
  BBlake2b *blake = ObjectWrap::Unwrap<BBlake2b>(info.Holder());

  uint32_t outlen = 32;

  if (info.Length() > 0 && !IsNull(info[0])) {
    if (!info[0]->IsNumber())
      return Nan::ThrowTypeError("First argument must be a number.");

    outlen = info[0]->Uint32Value();

    if (outlen == 0 || outlen > BCRYPTO_BLAKE2B_OUTBYTES)
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

    if (keylen > BCRYPTO_BLAKE2B_OUTBYTES)
      return Nan::ThrowTypeError("Bad key size.");
  }

  if (keylen > 0) {
    if (bcrypto_blake2b_init_key(&blake->ctx, outlen, key, keylen) < 0)
      return Nan::ThrowTypeError("Could not allocate context");
  } else {
    if (bcrypto_blake2b_init(&blake->ctx, outlen) < 0)
      return Nan::ThrowTypeError("Could not allocate context");
  }

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BBlake2b::Update) {
  BBlake2b *blake = ObjectWrap::Unwrap<BBlake2b>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("blake2b.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  bcrypto_blake2b_update(&blake->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BBlake2b::Final) {
  BBlake2b *blake = ObjectWrap::Unwrap<BBlake2b>(info.Holder());

  uint32_t outlen = blake->ctx.outlen;

  bcrypto_blake2b_final(&blake->ctx, global_out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BBlake2b::Digest) {
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

    if (outlen == 0 || outlen > BCRYPTO_BLAKE2B_OUTBYTES)
      return Nan::ThrowTypeError("Second argument must be a number.");
  }

  if (info.Length() > 2 && !IsNull(info[2])) {
    v8::Local<v8::Object> kbuf = info[2].As<v8::Object>();

    if (!node::Buffer::HasInstance(kbuf))
      return Nan::ThrowTypeError("Third argument must be a buffer.");

    key = (uint8_t *)node::Buffer::Data(kbuf);
    keylen = node::Buffer::Length(kbuf);

    if (keylen > BCRYPTO_BLAKE2B_OUTBYTES)
      return Nan::ThrowTypeError("Third argument must be a number.");
  }

  if (keylen > 0) {
    if (bcrypto_blake2b_init_key(&global_ctx, outlen, key, keylen) < 0)
      return Nan::ThrowTypeError("Could not allocate context.");
  } else {
    if (bcrypto_blake2b_init(&global_ctx, outlen) < 0)
      return Nan::ThrowTypeError("Could not allocate context.");
  }

  bcrypto_blake2b_update(&global_ctx, in, inlen);
  bcrypto_blake2b_final(&global_ctx, global_out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BBlake2b::Root) {
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

  if (bcrypto_blake2b_init(&global_ctx, outlen) < 0)
    return Nan::ThrowTypeError("Could not allocate context.");

  bcrypto_blake2b_update(&global_ctx, left, leftlen);
  bcrypto_blake2b_update(&global_ctx, right, rightlen);
  bcrypto_blake2b_final(&global_ctx, global_out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BBlake2b::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("blake2b.multi() requires arguments.");

  v8::Local<v8::Object> onebuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(onebuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *one = (uint8_t *)node::Buffer::Data(onebuf);
  size_t onelen = node::Buffer::Length(onebuf);

  v8::Local<v8::Object> twobuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(twobuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *two = (uint8_t *)node::Buffer::Data(twobuf);
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

  uint32_t outlen = 32;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsNumber())
      return Nan::ThrowTypeError("Fourth argument must be a number.");

    outlen = info[3]->Uint32Value();
  }

  if (bcrypto_blake2b_init(&global_ctx, outlen) < 0)
    return Nan::ThrowTypeError("Could not allocate context.");

  bcrypto_blake2b_update(&global_ctx, one, onelen);
  bcrypto_blake2b_update(&global_ctx, two, twolen);

  if (three)
    bcrypto_blake2b_update(&global_ctx, three, threelen);

  bcrypto_blake2b_final(&global_ctx, global_out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BBlake2b::Mac) {
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

  if (keylen > BCRYPTO_BLAKE2B_OUTBYTES)
    return Nan::ThrowTypeError("Second argument must be a number.");

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsNumber())
      return Nan::ThrowTypeError("Third argument must be a number.");

    outlen = info[2]->Uint32Value();

    if (outlen == 0 || outlen > BCRYPTO_BLAKE2B_OUTBYTES)
      return Nan::ThrowTypeError("Third argument must be a number.");
  }

  if (keylen > 0) {
    if (bcrypto_blake2b_init_key(&global_ctx, outlen, key, keylen) < 0)
      return Nan::ThrowTypeError("Could not allocate context.");
  } else {
    if (bcrypto_blake2b_init(&global_ctx, outlen) < 0)
      return Nan::ThrowTypeError("Could not allocate context.");
  }

  bcrypto_blake2b_update(&global_ctx, in, inlen);
  bcrypto_blake2b_final(&global_ctx, global_out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;
  return obj->IsNull() || obj->IsUndefined();
}
