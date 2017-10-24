#include "chacha20.h"

static Nan::Persistent<v8::FunctionTemplate> chacha20_constructor;

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj);

ChaCha20::ChaCha20() {
  memset(&ctx, 0, sizeof(chacha20_ctx));
  ctx.iv_size = 8;
}

ChaCha20::~ChaCha20() {}

void
ChaCha20::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(ChaCha20::New);

  chacha20_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("ChaCha20").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", ChaCha20::Init);
  Nan::SetPrototypeMethod(tpl, "initIV", ChaCha20::InitIV);
  Nan::SetPrototypeMethod(tpl, "initKey", ChaCha20::InitKey);
  Nan::SetPrototypeMethod(tpl, "encrypt", ChaCha20::Encrypt);
  Nan::SetPrototypeMethod(tpl, "setCounter", ChaCha20::SetCounter);
  Nan::SetPrototypeMethod(tpl, "getCounter", ChaCha20::GetCounter);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(chacha20_constructor);

  target->Set(Nan::New("ChaCha20").ToLocalChecked(), ctor->GetFunction());
}

void
ChaCha20::InitKey(char *key, size_t len) {
  Nan::HandleScope scope;

  if (len != 32)
    return Nan::ThrowError("Invalid key size.");

  chacha20_keysetup(&ctx, (uint8_t *)key, 32);
}

void
ChaCha20::InitIV(char *iv, size_t len, uint64_t ctr) {
  Nan::HandleScope scope;

  if (len != 8 && len != 12)
    return Nan::ThrowError("Invalid IV size.");

  chacha20_ivsetup(&ctx, (uint8_t *)iv, (uint8_t)len);
  chacha20_counter_set(&ctx, ctr);
}

NAN_METHOD(ChaCha20::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create ChaCha20 instance.");

  ChaCha20 *chacha = new ChaCha20();
  chacha->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(ChaCha20::Init) {
  ChaCha20 *chacha = ObjectWrap::Unwrap<ChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.init() requires arguments.");

  if (!IsNull(info[0])) {
    v8::Local<v8::Object> key = info[0].As<v8::Object>();

    if (!node::Buffer::HasInstance(key))
      return Nan::ThrowTypeError("First argument must be a buffer.");

    chacha->InitKey(node::Buffer::Data(key), node::Buffer::Length(key));
  }

  if (info.Length() > 1 && !IsNull(info[1])) {
    v8::Local<v8::Value> iv = info[1].As<v8::Object>();

    if (!node::Buffer::HasInstance(iv))
      return Nan::ThrowTypeError("Second argument must be a buffer.");

    uint64_t ctr = 0;

    if (info.Length() > 2 && !IsNull(info[2])) {
      if (!info[2]->IsNumber())
        return Nan::ThrowTypeError("Third argument must be a number.");

      ctr = (uint64_t)info[2]->IntegerValue();
    }

    chacha->InitIV(node::Buffer::Data(iv), node::Buffer::Length(iv), ctr);
  }

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(ChaCha20::InitKey) {
  ChaCha20 *chacha = ObjectWrap::Unwrap<ChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.initKey() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  chacha->InitKey(node::Buffer::Data(buf), node::Buffer::Length(buf));

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(ChaCha20::InitIV) {
  ChaCha20 *chacha = ObjectWrap::Unwrap<ChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.initIV() requires arguments.");

  v8::Local<v8::Object> iv = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(iv))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  uint64_t ctr = 0;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsNumber())
      return Nan::ThrowTypeError("Second argument must be a number.");

    ctr = (uint64_t)info[1]->IntegerValue();
  }

  chacha->InitIV(node::Buffer::Data(iv), node::Buffer::Length(iv), ctr);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(ChaCha20::Encrypt) {
  ChaCha20 *chacha = ObjectWrap::Unwrap<ChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.encrypt() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  chacha20_encrypt(&chacha->ctx, (uint8_t *)data, (uint8_t *)data, len);

  info.GetReturnValue().Set(buf);
}

NAN_METHOD(ChaCha20::SetCounter) {
  ChaCha20 *chacha = ObjectWrap::Unwrap<ChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.setCounter() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowError("First argument must be a number.");

  chacha20_counter_set(&chacha->ctx, (uint64_t)info[0]->IntegerValue());
}

NAN_METHOD(ChaCha20::GetCounter) {
  ChaCha20 *chacha = ObjectWrap::Unwrap<ChaCha20>(info.Holder());
  info.GetReturnValue().Set(
    Nan::New<v8::Number>((double)chacha20_counter_get(&chacha->ctx)));
}

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;
  return obj->IsNull() || obj->IsUndefined();
}
