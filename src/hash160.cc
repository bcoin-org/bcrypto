#include "hash160.h"
#include "openssl/ripemd.h"

static SHA256_CTX global_sctx;
static RIPEMD160_CTX global_rctx;
static uint8_t global_out[32];

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj);

static Nan::Persistent<v8::FunctionTemplate> hash160_constructor;

BHash160::BHash160() {
  memset(&ctx, 0, sizeof(SHA256_CTX));
}

BHash160::~BHash160() {}

void
BHash160::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BHash160::New);

  hash160_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Hash160").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BHash160::Init);
  Nan::SetPrototypeMethod(tpl, "update", BHash160::Update);
  Nan::SetPrototypeMethod(tpl, "final", BHash160::Final);
  Nan::SetMethod(tpl, "digest", BHash160::Digest);
  Nan::SetMethod(tpl, "root", BHash160::Root);
  Nan::SetMethod(tpl, "multi", BHash160::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(hash160_constructor);

  target->Set(Nan::New("Hash160").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BHash160::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create BHash160 instance.");

  BHash160 *hash = new BHash160();
  hash->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHash160::Init) {
  BHash160 *hash = ObjectWrap::Unwrap<BHash160>(info.Holder());

  SHA256_Init(&hash->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHash160::Update) {
  BHash160 *hash = ObjectWrap::Unwrap<BHash160>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("hash160.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA256_Update(&hash->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHash160::Final) {
  BHash160 *hash = ObjectWrap::Unwrap<BHash160>(info.Holder());

  SHA256_Final(global_out, &hash->ctx);

  RIPEMD160_Init(&global_rctx);
  RIPEMD160_Update(&global_rctx, global_out, 32);
  RIPEMD160_Final(global_out, &global_rctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 20).ToLocalChecked());
}

NAN_METHOD(BHash160::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("hash160.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA256_Init(&global_sctx);
  SHA256_Update(&global_sctx, in, inlen);
  SHA256_Final(global_out, &global_sctx);

  RIPEMD160_Init(&global_rctx);
  RIPEMD160_Update(&global_rctx, global_out, 32);
  RIPEMD160_Final(global_out, &global_rctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 20).ToLocalChecked());
}

NAN_METHOD(BHash160::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("hash160.root() requires arguments.");

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

  if (leftlen != 32 || rightlen != 32)
    return Nan::ThrowTypeError("Bad node sizes.");

  SHA256_Init(&global_sctx);
  SHA256_Update(&global_sctx, left, leftlen);
  SHA256_Update(&global_sctx, right, rightlen);
  SHA256_Final(global_out, &global_sctx);

  RIPEMD160_Init(&global_rctx);
  RIPEMD160_Update(&global_rctx, global_out, 32);
  RIPEMD160_Final(global_out, &global_rctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 20).ToLocalChecked());
}

NAN_METHOD(BHash160::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("hash160.multi() requires arguments.");

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

  SHA256_Init(&global_sctx);
  SHA256_Update(&global_sctx, one, onelen);
  SHA256_Update(&global_sctx, two, twolen);
  if (three)
    SHA256_Update(&global_sctx, three, threelen);
  SHA256_Final(global_out, &global_sctx);

  RIPEMD160_Init(&global_rctx);
  RIPEMD160_Update(&global_rctx, global_out, 32);
  RIPEMD160_Final(global_out, &global_rctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&global_out[0], 20).ToLocalChecked());
}

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;
  return obj->IsNull() || obj->IsUndefined();
}
