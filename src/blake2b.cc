#include "common.h"
#include "blake2b.h"

static bcrypto_blake2b_ctx global_ctx;
static uint8_t global_out[BCRYPTO_BLAKE2B_OUTBYTES];

static Nan::Persistent<v8::FunctionTemplate> blake2b_constructor;

BBLAKE2b::BBLAKE2b() {
  memset(&ctx, 0, sizeof(bcrypto_blake2b_ctx));
}

BBLAKE2b::~BBLAKE2b() {}

void
BBLAKE2b::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BBLAKE2b::New);

  blake2b_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("BLAKE2b").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BBLAKE2b::Init);
  Nan::SetPrototypeMethod(tpl, "update", BBLAKE2b::Update);
  Nan::SetPrototypeMethod(tpl, "final", BBLAKE2b::Final);
  Nan::SetMethod(tpl, "digest", BBLAKE2b::Digest);
  Nan::SetMethod(tpl, "root", BBLAKE2b::Root);
  Nan::SetMethod(tpl, "multi", BBLAKE2b::Multi);
  Nan::SetMethod(tpl, "mac", BBLAKE2b::Mac);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(blake2b_constructor);

  target->Set(Nan::New("BLAKE2b").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BBLAKE2b::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create BBLAKE2b instance.");

  BBLAKE2b *blake = new BBLAKE2b();
  blake->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BBLAKE2b::Init) {
  BBLAKE2b *blake = ObjectWrap::Unwrap<BBLAKE2b>(info.Holder());

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

NAN_METHOD(BBLAKE2b::Update) {
  BBLAKE2b *blake = ObjectWrap::Unwrap<BBLAKE2b>(info.Holder());

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

NAN_METHOD(BBLAKE2b::Final) {
  BBLAKE2b *blake = ObjectWrap::Unwrap<BBLAKE2b>(info.Holder());

  uint32_t outlen = blake->ctx.outlen;

  bcrypto_blake2b_final(&blake->ctx, global_out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BBLAKE2b::Digest) {
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

NAN_METHOD(BBLAKE2b::Root) {
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

NAN_METHOD(BBLAKE2b::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("blake2b.multi() requires arguments.");

  v8::Local<v8::Object> xbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(xbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *x = (uint8_t *)node::Buffer::Data(xbuf);
  size_t xlen = node::Buffer::Length(xbuf);

  v8::Local<v8::Object> ybuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(ybuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *y = (uint8_t *)node::Buffer::Data(ybuf);
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

  uint32_t outlen = 32;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsNumber())
      return Nan::ThrowTypeError("Fourth argument must be a number.");

    outlen = info[3]->Uint32Value();
  }

  if (bcrypto_blake2b_init(&global_ctx, outlen) < 0)
    return Nan::ThrowTypeError("Could not allocate context.");

  bcrypto_blake2b_update(&global_ctx, x, xlen);
  bcrypto_blake2b_update(&global_ctx, y, ylen);

  if (z)
    bcrypto_blake2b_update(&global_ctx, z, zlen);

  bcrypto_blake2b_final(&global_ctx, global_out, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BBLAKE2b::Mac) {
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
