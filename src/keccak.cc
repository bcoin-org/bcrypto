#include "common.h"
#include "keccak.h"

static bcrypto_keccak_ctx global_ctx;
static uint8_t global_out[64];

static Nan::Persistent<v8::FunctionTemplate> keccak_constructor;

BKeccak::BKeccak() {
  memset(&ctx, 0, sizeof(bcrypto_keccak_ctx));
}

BKeccak::~BKeccak() {}

void
BKeccak::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BKeccak::New);

  keccak_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Keccak").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BKeccak::Init);
  Nan::SetPrototypeMethod(tpl, "update", BKeccak::Update);
  Nan::SetPrototypeMethod(tpl, "final", BKeccak::Final);
  Nan::SetMethod(tpl, "digest", BKeccak::Digest);
  Nan::SetMethod(tpl, "root", BKeccak::Root);
  Nan::SetMethod(tpl, "multi", BKeccak::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(keccak_constructor);

  target->Set(Nan::New("Keccak").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BKeccak::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Keccak instance.");

  BKeccak *keccak = new BKeccak();
  keccak->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BKeccak::Init) {
  BKeccak *keccak = ObjectWrap::Unwrap<BKeccak>(info.Holder());

  uint32_t bits = 256;

  if (info.Length() > 0 && !IsNull(info[0])) {
    if (!info[0]->IsNumber())
      return Nan::ThrowTypeError("First argument must be a number.");

    bits = info[0]->Uint32Value();
  }

  if (!bcrypto_keccak_init(&keccak->ctx, bits))
    return Nan::ThrowError("Could not initialize context.");

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BKeccak::Update) {
  BKeccak *keccak = ObjectWrap::Unwrap<BKeccak>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("keccak.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  bcrypto_keccak_update(&keccak->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BKeccak::Final) {
  BKeccak *keccak = ObjectWrap::Unwrap<BKeccak>(info.Holder());

  int pad = 0x01;

  if (info.Length() > 0 && !IsNull(info[0])) {
    if (!info[0]->IsNumber())
      return Nan::ThrowTypeError("First argument must be a boolean.");

    pad = (int)info[0]->Uint32Value();
  }

  size_t outlen = 0;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsNumber())
      return Nan::ThrowTypeError("Second argument must be a number.");

    outlen = (size_t)info[1]->Uint32Value();
  }

  if (!bcrypto_keccak_final(&keccak->ctx, pad, &outlen, global_out))
    return Nan::ThrowError("Could not finalize context.");

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BKeccak::Digest) {
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

  int pad = 0x01;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsNumber())
      return Nan::ThrowTypeError("Third argument must be a number.");

    pad = (int)info[2]->Uint32Value();
  }

  if (!bcrypto_keccak_init(&global_ctx, bits))
    return Nan::ThrowError("Could not allocate context.");

  bcrypto_keccak_update(&global_ctx, in, inlen);

  size_t outlen = 0;

  assert(bcrypto_keccak_final(&global_ctx, pad, &outlen, global_out));

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BKeccak::Root) {
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
    return Nan::ThrowError("Bad node sizes.");

  int pad = 0x01;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsNumber())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    pad = (int)info[3]->Uint32Value();
  }

  if (!bcrypto_keccak_init(&global_ctx, bits))
    return Nan::ThrowError("Could not initialize context.");

  bcrypto_keccak_update(&global_ctx, left, leftlen);
  bcrypto_keccak_update(&global_ctx, right, rightlen);

  size_t outlen = 0;

  assert(bcrypto_keccak_final(&global_ctx, pad, &outlen, global_out));

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BKeccak::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("keccak.multi() requires arguments.");

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

  uint32_t bits = 256;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsNumber())
      return Nan::ThrowTypeError("Fourth argument must be a number.");

    bits = info[3]->Uint32Value();
  }

  int pad = 0x01;

  if (info.Length() > 4 && !IsNull(info[4])) {
    if (!info[4]->IsNumber())
      return Nan::ThrowTypeError("Fifth argument must be a boolean.");

    pad = (int)info[4]->Uint32Value();
  }

  if (!bcrypto_keccak_init(&global_ctx, bits))
    return Nan::ThrowError("Could not initialize context.");

  bcrypto_keccak_update(&global_ctx, one, onelen);
  bcrypto_keccak_update(&global_ctx, two, twolen);
  if (three)
    bcrypto_keccak_update(&global_ctx, three, threelen);

  size_t outlen = 0;

  assert(bcrypto_keccak_final(&global_ctx, pad, &outlen, global_out));

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}
