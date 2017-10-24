#include "keccak.h"

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj);

static Nan::Persistent<v8::FunctionTemplate> keccak_constructor;

Keccak::Keccak() {
  memset(&ctx, 0, sizeof(keccak_ctx));
}

Keccak::~Keccak() {}

void
Keccak::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(Keccak::New);

  keccak_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Keccak").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", Keccak::Init);
  Nan::SetPrototypeMethod(tpl, "update", Keccak::Update);
  Nan::SetPrototypeMethod(tpl, "final", Keccak::Final);
  Nan::SetMethod(tpl, "digest", Keccak::Digest);
  Nan::SetMethod(tpl, "root", Keccak::Root);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(keccak_constructor);

  target->Set(Nan::New("Keccak").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(Keccak::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Keccak instance.");

  Keccak *keccak = new Keccak();
  keccak->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Keccak::Init) {
  Keccak *keccak = ObjectWrap::Unwrap<Keccak>(info.Holder());

  uint32_t bits = 256;

  if (info.Length() > 0 && !IsNull(info[0])) {
    if (!info[0]->IsNumber())
      return Nan::ThrowTypeError("First argument must be a number.");

    bits = info[0]->Uint32Value();
  }

  switch (bits) {
    case 224:
      keccak_224_init(&keccak->ctx);
      break;
    case 256:
      keccak_256_init(&keccak->ctx);
      break;
    case 384:
      keccak_384_init(&keccak->ctx);
      break;
    case 512:
      keccak_512_init(&keccak->ctx);
      break;
    default:
      return Nan::ThrowTypeError("Could not allocate context.");
  }

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Keccak::Update) {
  Keccak *keccak = ObjectWrap::Unwrap<Keccak>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("keccak.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  keccak_update(&keccak->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Keccak::Final) {
  Keccak *keccak = ObjectWrap::Unwrap<Keccak>(info.Holder());

  bool std = false;

  if (info.Length() > 0 && !IsNull(info[0])) {
    if (!info[0]->IsBoolean())
      return Nan::ThrowTypeError("First argument must be a boolean.");

    std = info[0]->BooleanValue();
  }

  uint32_t outlen = 100 - keccak->ctx.block_size / 2;
  uint8_t out[64];

  if (std)
    sha3_final(&keccak->ctx, out);
  else
    keccak_final(&keccak->ctx, out);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], outlen).ToLocalChecked());
}

NAN_METHOD(Keccak::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("keccak.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  uint32_t bits = 256;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsNumber())
      return Nan::ThrowTypeError("Second argument must be a number.");

    bits = info[1]->Uint32Value();
  }

  bool std = false;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean.");

    std = info[2]->BooleanValue();
  }

  keccak_ctx ctx;

  switch (bits) {
    case 224:
      keccak_224_init(&ctx);
      break;
    case 256:
      keccak_256_init(&ctx);
      break;
    case 384:
      keccak_384_init(&ctx);
      break;
    case 512:
      keccak_512_init(&ctx);
      break;
    default:
      return Nan::ThrowTypeError("Could not allocate context.");
  }

  keccak_update(&ctx, in, inlen);

  uint32_t outlen = 100 - ctx.block_size / 2;
  uint8_t out[64];

  if (std)
    sha3_final(&ctx, out);
  else
    keccak_final(&ctx, out);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], outlen).ToLocalChecked());
}

NAN_METHOD(Keccak::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("keccak.root() requires arguments.");

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

  uint32_t bits = 256;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsNumber())
      return Nan::ThrowTypeError("Third argument must be a number.");

    bits = info[2]->Uint32Value();
  }

  if (leftlen != bits / 8 || rightlen != bits / 8)
    return Nan::ThrowTypeError("Bad node sizes.");

  bool std = false;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    std = info[3]->BooleanValue();
  }

  keccak_ctx ctx;

  switch (bits) {
    case 224:
      keccak_224_init(&ctx);
      break;
    case 256:
      keccak_256_init(&ctx);
      break;
    case 384:
      keccak_384_init(&ctx);
      break;
    case 512:
      keccak_512_init(&ctx);
      break;
    default:
      return Nan::ThrowTypeError("Could not allocate context.");
  }

  keccak_update(&ctx, left, leftlen);
  keccak_update(&ctx, right, rightlen);

  uint32_t outlen = 100 - ctx.block_size / 2;
  uint8_t out[64];

  if (std)
    sha3_final(&ctx, out);
  else
    keccak_final(&ctx, out);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], outlen).ToLocalChecked());
}

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;
  return obj->IsNull() || obj->IsUndefined();
}
