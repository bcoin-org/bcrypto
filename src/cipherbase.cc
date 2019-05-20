#include "common.h"
#include "cipherbase.h"

static Nan::Persistent<v8::FunctionTemplate> cipher_constructor;

static bool IsValidGCMTagLength(unsigned int tag_len) {
  return tag_len == 4 || tag_len == 8 || (tag_len >= 12 && tag_len <= 16);
}

BCipherBase::BCipherBase() {
  type = 0;
  mode = 0;
  encrypt = 0;
  first = 0;
  done = 0;
  memset(&tag[0], 0x00, 16);
  tag_len = 0;
  bcrypto_cipher_init(&ctx);
}

BCipherBase::~BCipherBase() {
  memset(&tag[0], 0x00, 16);
  tag_len = 0;
  bcrypto_cipher_clear(&ctx);
}

void
BCipherBase::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BCipherBase::New);

  cipher_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("CipherBase").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BCipherBase::Init);
  Nan::SetPrototypeMethod(tpl, "update", BCipherBase::Update);
  Nan::SetPrototypeMethod(tpl, "final", BCipherBase::Final);
  Nan::SetPrototypeMethod(tpl, "setAAD", BCipherBase::SetAAD);
  Nan::SetPrototypeMethod(tpl, "getAuthTag", BCipherBase::GetAuthTag);
  Nan::SetPrototypeMethod(tpl, "setAuthTag", BCipherBase::SetAuthTag);
  Nan::SetMethod(tpl, "hasCipher", BCipherBase::HasCipher);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(cipher_constructor);

  Nan::Set(target, Nan::New("CipherBase").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BCipherBase::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Cipher instance.");

  if (info.Length() < 3)
    return Nan::ThrowError("cipher requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  if (!info[2]->IsBoolean())
    return Nan::ThrowTypeError("Third argument must be a boolean.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  int mode = (int)Nan::To<uint32_t>(info[1]).FromJust();
  int encrypt = (int)Nan::To<bool>(info[2]).FromJust();

  BCipherBase *cipher = new BCipherBase();

  cipher->Wrap(info.This());
  cipher->type = type;
  cipher->mode = mode;
  cipher->encrypt = encrypt;

  if (!bcrypto_cipher_setup(&cipher->ctx, type, mode, encrypt))
    return Nan::ThrowError("Invalid cipher name.");

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BCipherBase::Init) {
  BCipherBase *cipher = ObjectWrap::Unwrap<BCipherBase>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("cipher.init() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);

  const uint8_t *iv = NULL;
  size_t iv_len = 0;

  if (info.Length() > 1 && !IsNull(info[1])) {
    v8::Local<v8::Value> iv_buf = info[1].As<v8::Object>();

    if (!node::Buffer::HasInstance(iv_buf))
      return Nan::ThrowTypeError("Second argument must be a buffer.");

    iv = (const uint8_t *)node::Buffer::Data(iv_buf);
    iv_len = node::Buffer::Length(iv_buf);
  }

  if (cipher->first || cipher->done) {
    if (!bcrypto_cipher_setup(&cipher->ctx, cipher->type,
                              cipher->mode, cipher->encrypt)) {
      return Nan::ThrowError("Invalid cipher name.");
    }
    cipher->done = 0;
    memset(&cipher->tag[0], 0x00, 16);
    cipher->tag_len = 0;
  } else {
    cipher->first = 1;
  }

  if (!bcrypto_cipher_set_key(&cipher->ctx, key, key_len))
    return Nan::ThrowRangeError("Invalid key size.");

  if (!bcrypto_cipher_set_iv(&cipher->ctx, iv, iv_len))
    return Nan::ThrowRangeError("Invalid IV size.");

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BCipherBase::Update) {
  BCipherBase *cipher = ObjectWrap::Unwrap<BCipherBase>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("cipher.update() requires arguments.");

  if (cipher->done)
    return Nan::ThrowError("Cipher is not initialized.");

  v8::Local<v8::Object> data_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(data_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(data_buf);
  size_t data_len = node::Buffer::Length(data_buf);

  size_t out_len = data_len + cipher->ctx.desc->block_size;
  uint8_t *out = (uint8_t *)malloc(out_len);

  if (out == NULL)
    return Nan::ThrowError("Failed to update cipher.");

  out_len = bcrypto_cipher_update(&cipher->ctx, out, data, data_len);

  if (out_len == 0) {
    free(out);
    out = NULL;
  }

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BCipherBase::Final) {
  BCipherBase *cipher = ObjectWrap::Unwrap<BCipherBase>(info.Holder());

  if (cipher->done)
    return Nan::ThrowError("Cipher is not initialized.");

  size_t block_size = cipher->ctx.desc->block_size;
  uint8_t *out = (uint8_t *)malloc(block_size);
  int out_len = -1;

  if (out == NULL)
    return Nan::ThrowError("Failed to finalize cipher.");

  out_len = bcrypto_cipher_final(&cipher->ctx, out);
  cipher->done = 1;

  if (out_len < 0) {
    free(out);
    return Nan::ThrowError("Invalid padding.");
  }

  if (out_len == 0) {
    free(out);
    out = NULL;
  }

  if (cipher->tag_len != 0) {
    if (!bcrypto_cipher_verify(&cipher->ctx, cipher->tag, cipher->tag_len))
      return Nan::ThrowError("Invalid MAC.");
    memset(&cipher->tag[0], 0x00, 16);
    cipher->tag_len = 0;
  }

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, (size_t)out_len).ToLocalChecked());
}

NAN_METHOD(BCipherBase::SetAAD) {
  BCipherBase *cipher = ObjectWrap::Unwrap<BCipherBase>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("cipher.setAAD() requires arguments.");

  if (cipher->done)
    return Nan::ThrowError("Cipher is not initialized.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  if (!bcrypto_cipher_auth(&cipher->ctx, data, len))
    return Nan::ThrowError("Could not set AAD.");

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BCipherBase::GetAuthTag) {
  BCipherBase *cipher = ObjectWrap::Unwrap<BCipherBase>(info.Holder());

  if (!cipher->done)
    return Nan::ThrowError("Cipher is not finalized.");

  if (!cipher->encrypt)
    return Nan::ThrowError("Cannot get auth tag when decrypting.");

  uint8_t tag[16];

  if (!bcrypto_cipher_digest(&cipher->ctx, &tag[0], 16))
    return Nan::ThrowError("Could not get auth tag.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&tag[0], 16).ToLocalChecked());
}

NAN_METHOD(BCipherBase::SetAuthTag) {
  BCipherBase *cipher = ObjectWrap::Unwrap<BCipherBase>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("cipher.setAuthTag() requires arguments.");

  if (cipher->done)
    return Nan::ThrowError("Cipher is not initialized.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  if (!IsValidGCMTagLength(len))
    return Nan::ThrowRangeError("Invalid tag length.");

  if (cipher->encrypt)
    return Nan::ThrowError("Cannot set auth tag when encrypting.");

  memcpy(&cipher->tag[0], data, len);
  cipher->tag_len = len;

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BCipherBase::HasCipher) {
  if (info.Length() < 2)
    return Nan::ThrowError("cipher.hasCipher() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  int type = (int)Nan::To<uint32_t>(info[0]).FromJust();
  int mode = (int)Nan::To<uint32_t>(info[1]).FromJust();
  int result = bcrypto_cipher_get(type) != NULL;

  result &= (mode >= BCRYPTO_MODE_MIN && mode <= BCRYPTO_MODE_MAX);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
