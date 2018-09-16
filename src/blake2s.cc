#include "common.h"
#include "blake2s.h"

static bcrypto_blake2s_ctx global_ctx;
static uint8_t global_out[BCRYPTO_BLAKE2S_OUTBYTES];

static Nan::Persistent<v8::FunctionTemplate> blake2s_constructor;

BBLAKE2s::BBLAKE2s() {
  memset(&ctx, 0, sizeof(bcrypto_blake2s_ctx));
}

BBLAKE2s::~BBLAKE2s() {}

void
BBLAKE2s::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BBLAKE2s::New);

  blake2s_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("BLAKE2s").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BBLAKE2s::Init);
  Nan::SetPrototypeMethod(tpl, "update", BBLAKE2s::Update);
  Nan::SetPrototypeMethod(tpl, "final", BBLAKE2s::Final);
  Nan::SetMethod(tpl, "digest", BBLAKE2s::Digest);
  Nan::SetMethod(tpl, "root", BBLAKE2s::Root);
  Nan::SetMethod(tpl, "multi", BBLAKE2s::Multi);
  Nan::SetMethod(tpl, "mac", BBLAKE2s::Mac);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(blake2s_constructor);

  target->Set(Nan::New("BLAKE2s").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BBLAKE2s::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create BBLAKE2s instance.");

  BBLAKE2s *blake = new BBLAKE2s();
  blake->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BBLAKE2s::Init) {
  BBLAKE2s *blake = ObjectWrap::Unwrap<BBLAKE2s>(info.Holder());

  uint32_t outlen = 32;

  if (info.Length() > 0 && !IsNull(info[0])) {
    if (!info[0]->IsNumber())
      return Nan::ThrowTypeError("First argument must be a number.");

    outlen = info[0]->Uint32Value();

    if (outlen == 0 || outlen > BCRYPTO_BLAKE2S_OUTBYTES)
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

    if (keylen > BCRYPTO_BLAKE2S_OUTBYTES)
      return Nan::ThrowTypeError("Bad key size.");
  }

  if (keylen > 0) {
    if (bcrypto_blake2s_init_key(&blake->ctx, outlen, key, keylen) < 0)
      return Nan::ThrowTypeError("Could not allocate context");
  } else {
    if (bcrypto_blake2s_init(&blake->ctx, outlen) < 0)
      return Nan::ThrowTypeError("Could not allocate context");
  }

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BBLAKE2s::Update) {
  BBLAKE2s *blake = ObjectWrap::Unwrap<BBLAKE2s>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("blake2s.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  bcrypto_blake2s_update(&blake->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BBLAKE2s::Final) {
  BBLAKE2s *blake = ObjectWrap::Unwrap<BBLAKE2s>(info.Holder());

  uint32_t outlen = blake->ctx.outlen;

  bcrypto_blake2s_final(&blake->ctx, global_out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BBLAKE2s::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("blake2s.digest() requires arguments.");

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

    if (outlen == 0 || outlen > BCRYPTO_BLAKE2S_OUTBYTES)
      return Nan::ThrowTypeError("Second argument must be a number.");
  }

  if (info.Length() > 2 && !IsNull(info[2])) {
    v8::Local<v8::Object> kbuf = info[2].As<v8::Object>();

    if (!node::Buffer::HasInstance(kbuf))
      return Nan::ThrowTypeError("Third argument must be a buffer.");

    key = (uint8_t *)node::Buffer::Data(kbuf);
    keylen = node::Buffer::Length(kbuf);

    if (keylen > BCRYPTO_BLAKE2S_OUTBYTES)
      return Nan::ThrowTypeError("Third argument must be a number.");
  }

  if (keylen > 0) {
    if (bcrypto_blake2s_init_key(&global_ctx, outlen, key, keylen) < 0)
      return Nan::ThrowTypeError("Could not allocate context.");
  } else {
    if (bcrypto_blake2s_init(&global_ctx, outlen) < 0)
      return Nan::ThrowTypeError("Could not allocate context.");
  }

  bcrypto_blake2s_update(&global_ctx, in, inlen);
  bcrypto_blake2s_final(&global_ctx, global_out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BBLAKE2s::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("blake2s.root() requires arguments.");

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

  if (bcrypto_blake2s_init(&global_ctx, outlen) < 0)
    return Nan::ThrowTypeError("Could not allocate context.");

  bcrypto_blake2s_update(&global_ctx, left, leftlen);
  bcrypto_blake2s_update(&global_ctx, right, rightlen);
  bcrypto_blake2s_final(&global_ctx, global_out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BBLAKE2s::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("blake2s.multi() requires arguments.");

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

  if (bcrypto_blake2s_init(&global_ctx, outlen) < 0)
    return Nan::ThrowTypeError("Could not allocate context.");

  bcrypto_blake2s_update(&global_ctx, one, onelen);
  bcrypto_blake2s_update(&global_ctx, two, twolen);

  if (three)
    bcrypto_blake2s_update(&global_ctx, three, threelen);

  bcrypto_blake2s_final(&global_ctx, global_out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BBLAKE2s::Mac) {
  if (info.Length() < 2)
    return Nan::ThrowError("blake2s.mac() requires arguments.");

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

  if (keylen > BCRYPTO_BLAKE2S_OUTBYTES)
    return Nan::ThrowTypeError("Second argument must be a number.");

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsNumber())
      return Nan::ThrowTypeError("Third argument must be a number.");

    outlen = info[2]->Uint32Value();

    if (outlen == 0 || outlen > BCRYPTO_BLAKE2S_OUTBYTES)
      return Nan::ThrowTypeError("Third argument must be a number.");
  }

  if (keylen > 0) {
    if (bcrypto_blake2s_init_key(&global_ctx, outlen, key, keylen) < 0)
      return Nan::ThrowTypeError("Could not allocate context.");
  } else {
    if (bcrypto_blake2s_init(&global_ctx, outlen) < 0)
      return Nan::ThrowTypeError("Could not allocate context.");
  }

  bcrypto_blake2s_update(&global_ctx, in, inlen);
  bcrypto_blake2s_final(&global_ctx, global_out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}
