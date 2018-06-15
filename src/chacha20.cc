#include "chacha20.h"

static Nan::Persistent<v8::FunctionTemplate> chacha20_constructor;

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj);

BChaCha20::BChaCha20() {
  memset(&ctx, 0, sizeof(bcrypto_chacha20_ctx));
  ctx.nonce_size = 8;
}

BChaCha20::~BChaCha20() {}

void
BChaCha20::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BChaCha20::New);

  chacha20_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("ChaCha20").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BChaCha20::Init);
  Nan::SetPrototypeMethod(tpl, "initIV", BChaCha20::InitIV);
  Nan::SetPrototypeMethod(tpl, "initKey", BChaCha20::InitKey);
  Nan::SetPrototypeMethod(tpl, "encrypt", BChaCha20::Encrypt);
  Nan::SetPrototypeMethod(tpl, "setCounter", BChaCha20::SetCounter);
  Nan::SetPrototypeMethod(tpl, "getCounter", BChaCha20::GetCounter);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(chacha20_constructor);

  target->Set(Nan::New("ChaCha20").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BChaCha20::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create BChaCha20 instance.");

  BChaCha20 *chacha = new BChaCha20();
  chacha->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BChaCha20::Init) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.init() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Value> iv_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(iv_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *key = (uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);

  if (key_len < 32)
    return Nan::ThrowError("Invalid key size.");

  const uint8_t *iv = (uint8_t *)node::Buffer::Data(iv_buf);
  size_t iv_len = node::Buffer::Length(iv_buf);

  if (iv_len != 8 && iv_len != 12)
    return Nan::ThrowError("Invalid IV size.");

  uint64_t ctr = 0;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsNumber())
      return Nan::ThrowTypeError("Third argument must be a number.");

    ctr = (uint64_t)info[2]->IntegerValue();
  }

  bcrypto_chacha20_keysetup(&chacha->ctx, (uint8_t *)key, 32);
  bcrypto_chacha20_ivsetup(&chacha->ctx, (uint8_t *)iv, (uint8_t)iv_len);
  bcrypto_chacha20_counter_set(&chacha->ctx, ctr);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BChaCha20::InitKey) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.initKey() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *key = (uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);

  if (key_len < 32)
    return Nan::ThrowError("Invalid key size.");

  bcrypto_chacha20_keysetup(&chacha->ctx, (uint8_t *)key, 32);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BChaCha20::InitIV) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.initIV() requires arguments.");

  v8::Local<v8::Object> iv_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(iv_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *iv = (uint8_t *)node::Buffer::Data(iv_buf);
  size_t iv_len = node::Buffer::Length(iv_buf);

  if (iv_len != 8 && iv_len != 12)
    return Nan::ThrowError("Invalid IV size.");

  uint64_t ctr = 0;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsNumber())
      return Nan::ThrowTypeError("Second argument must be a number.");

    ctr = (uint64_t)info[1]->IntegerValue();
  }

  bcrypto_chacha20_ivsetup(&chacha->ctx, (uint8_t *)iv, (uint8_t)iv_len);
  bcrypto_chacha20_counter_set(&chacha->ctx, ctr);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BChaCha20::Encrypt) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.encrypt() requires arguments.");

  v8::Local<v8::Object> data_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(data_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(data_buf);
  size_t data_len = node::Buffer::Length(data_buf);

  bcrypto_chacha20_encrypt(&chacha->ctx, data, (uint8_t *)data, data_len);

  info.GetReturnValue().Set(data_buf);
}

NAN_METHOD(BChaCha20::SetCounter) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.setCounter() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowError("First argument must be a number.");

  bcrypto_chacha20_counter_set(&chacha->ctx, (uint64_t)info[0]->IntegerValue());
}

NAN_METHOD(BChaCha20::GetCounter) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());
  info.GetReturnValue().Set(
    Nan::New<v8::Number>((double)bcrypto_chacha20_counter_get(&chacha->ctx)));
}

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;
  return obj->IsNull() || obj->IsUndefined();
}
