#include "common.h"
#include "cipherbase.h"
#include "openssl/evp.h"

static Nan::Persistent<v8::FunctionTemplate> cipher_constructor;

BCipherBase::BCipherBase() {
  type = NULL;
  encrypt = false;
  ctx = NULL;
}

BCipherBase::~BCipherBase() {
  type = NULL;
  encrypt = false;
  if (ctx) {
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
  }
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
  Nan::SetMethod(tpl, "hasCipher", BCipherBase::HasCipher);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(cipher_constructor);

  target->Set(Nan::New("CipherBase").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BCipherBase::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Cipher instance.");

  if (info.Length() < 2)
    return Nan::ThrowError("cipher requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("Argument must be a string.");

  if (!info[1]->IsBoolean())
    return Nan::ThrowTypeError("Argument must be a boolean.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;
  bool encrypt = info[1]->BooleanValue();

  const EVP_CIPHER *type = EVP_get_cipherbyname(name);

  if (!type)
    return Nan::ThrowError("Invalid cipher name.");

  int mode = EVP_CIPHER_mode(type);

  if (mode != EVP_CIPH_ECB_MODE
      && mode != EVP_CIPH_CBC_MODE
      && mode != EVP_CIPH_CTR_MODE
      && mode != EVP_CIPH_CFB_MODE
      && mode != EVP_CIPH_OFB_MODE) {
    return Nan::ThrowError("Invalid cipher mode.");
  }

  BCipherBase *cipher = new BCipherBase();
  cipher->type = type;
  cipher->encrypt = encrypt;
  cipher->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BCipherBase::Init) {
  BCipherBase *cipher = ObjectWrap::Unwrap<BCipherBase>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("cipher.init() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Argument must be a buffer.");

  const uint8_t *key = (uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);

  const uint8_t *iv = NULL;
  int iv_len = -1;

  if (info.Length() > 1 && !IsNull(info[1])) {
    v8::Local<v8::Value> iv_buf = info[1].As<v8::Object>();

    if (!node::Buffer::HasInstance(iv_buf))
      return Nan::ThrowTypeError("Argument must be a buffer.");

    iv = (uint8_t *)node::Buffer::Data(iv_buf);
    iv_len = node::Buffer::Length(iv_buf);
  }

  int expected_iv_len = EVP_CIPHER_iv_length(cipher->type);
  bool has_iv = iv_len >= 0;

  if ((!has_iv && expected_iv_len != 0)
      || (has_iv && iv_len != expected_iv_len)) {
    return Nan::ThrowError("Invalid IV length.");
  }

  if (cipher->ctx) {
    EVP_CIPHER_CTX_free(cipher->ctx);
    cipher->ctx = NULL;
  }

  cipher->ctx = EVP_CIPHER_CTX_new();

  if (!cipher->ctx)
    return Nan::ThrowError("Failed to initialize cipher.");

  int r = EVP_CipherInit_ex(cipher->ctx, cipher->type, NULL,
                             NULL, NULL, cipher->encrypt);

  if (r != 1)
    return Nan::ThrowError("Failed to initialize cipher.");

  if (!EVP_CIPHER_CTX_set_key_length(cipher->ctx, key_len))
    return Nan::ThrowError("Invalid key length.");

  r = EVP_CipherInit_ex(cipher->ctx, NULL, NULL, key, iv, cipher->encrypt);

  if (r != 1)
    return Nan::ThrowError("Failed to initialize cipher.");

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BCipherBase::Update) {
  BCipherBase *cipher = ObjectWrap::Unwrap<BCipherBase>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("cipher.update() requires arguments.");

  if (!cipher->ctx)
    return Nan::ThrowError("Cipher is not initialized.");

  v8::Local<v8::Object> data_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(data_buf))
    return Nan::ThrowTypeError("Argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(data_buf);
  size_t data_len = node::Buffer::Length(data_buf);

  int buff_len = data_len + EVP_CIPHER_CTX_block_size(cipher->ctx);
  uint8_t *out = (uint8_t *)malloc(buff_len);
  int out_len;

  if (!out)
    return Nan::ThrowError("Failed to update cipher.");

  int r = EVP_CipherUpdate(cipher->ctx, out, &out_len, data, data_len);

  assert(out_len <= buff_len);

  if (r != 1) {
    free(out);
    return Nan::ThrowError("Failed to update cipher.");
  }

  if (out_len == 0) {
    free(out);
    out = NULL;
  }

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BCipherBase::Final) {
  BCipherBase *cipher = ObjectWrap::Unwrap<BCipherBase>(info.Holder());

  if (!cipher->ctx)
    return Nan::ThrowError("Cipher is not initialized.");

  size_t block_size = EVP_CIPHER_CTX_block_size(cipher->ctx);
  uint8_t *out = (uint8_t *)malloc(block_size);
  int out_len = -1;

  if (!out)
    return Nan::ThrowError("Failed to finalize cipher.");

  int r = EVP_CipherFinal_ex(cipher->ctx, out, &out_len);

  if (r != 1 || out_len < 0) {
    free(out);
    return Nan::ThrowError("Failed to finalize cipher.");
  }

  EVP_CIPHER_CTX_free(cipher->ctx);
  cipher->ctx = NULL;

  if (out_len == 0) {
    free(out);
    out = NULL;
  }

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, (size_t)out_len).ToLocalChecked());
}

NAN_METHOD(BCipherBase::HasCipher) {
  if (info.Length() < 1)
    return Nan::ThrowError("cipher.hasCipher() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("Argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;
  bool result = EVP_get_cipherbyname(name) != NULL;

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
