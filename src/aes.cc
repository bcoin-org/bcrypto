#include "aes.h"

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj);

static const uint32_t FINALIZED = 0x80000000;

static Nan::Persistent<v8::FunctionTemplate> aes_constructor;

static inline void
XOR(uint8_t *out, uint8_t *a, uint8_t *b) {
  uint32_t i;
  for (i = 0; i < 16; i++)
    out[i] = a[i] ^ b[i];
}

#define AES_ENCRYPT(in, ipos, out, opos) do { \
  if (aes->chain) { \
    XOR(out + opos, in + ipos, aes->prev); \
    AES_encrypt(out + opos, out + opos, &aes->key); \
    memcpy(aes->prev, out + opos, 16); \
  } else { \
    AES_encrypt(in + ipos, out + opos, &aes->key); \
  } \
} while (0)

AESCipher::AESCipher() {
  bits = 256;
  chain = false;
  memset(&key, 0, sizeof(AES_KEY));
  memset(&prev, 0, 16 * sizeof(uint8_t));
  memset(&block, 0, 16 * sizeof(uint8_t));
  bpos = FINALIZED;
}

AESCipher::~AESCipher() {}

void
AESCipher::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(AESCipher::New);

  aes_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("AESCipher").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", AESCipher::Init);
  Nan::SetPrototypeMethod(tpl, "update", AESCipher::Update);
  Nan::SetPrototypeMethod(tpl, "final", AESCipher::Final);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(aes_constructor);

  target->Set(Nan::New("AESCipher").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(AESCipher::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create AESCipher instance.");

  AESCipher *aes = new AESCipher();

  uint32_t bits = 256;
  bool chain = false;

  if (info.Length() > 0 && !IsNull(info[0])) {
    if (!info[0]->IsNumber())
      return Nan::ThrowTypeError("First argument must be a number.");

    bits = info[0]->Uint32Value();

    if (bits != 128 && bits != 192 && bits != 256)
      return Nan::ThrowTypeError("First argument must be a number.");
  }

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("First argument must be a number.");

    chain = info[1]->BooleanValue();
  }

  aes->bits = bits;
  aes->chain = chain;

  aes->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(AESCipher::Init) {
  AESCipher *aes = ObjectWrap::Unwrap<AESCipher>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("AESCipher.init() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *key = (uint8_t *)node::Buffer::Data(buf);
  size_t keylen = node::Buffer::Length(buf);

  if (keylen != 32)
    return Nan::ThrowError("Invalid key size.");

  if (info.Length() > 1 && !IsNull(info[1])) {
    v8::Local<v8::Object> buf = info[1].As<v8::Object>();

    if (!node::Buffer::HasInstance(buf))
      return Nan::ThrowTypeError("Second argument must be a buffer.");

    uint8_t *iv = (uint8_t *)node::Buffer::Data(buf);
    size_t ivlen = node::Buffer::Length(buf);

    if (ivlen != 16)
      return Nan::ThrowError("Invalid IV size.");

    memcpy(aes->prev, iv, 16);
  } else {
    if (aes->chain)
      return Nan::ThrowTypeError("Second argument must be a buffer.");
  }

  AES_set_encrypt_key(key, aes->bits, &aes->key);
  aes->bpos = 0;

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(AESCipher::Update) {
  AESCipher *aes = ObjectWrap::Unwrap<AESCipher>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("AESCipher.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (aes->bpos & FINALIZED)
    return Nan::ThrowError("Context is already finalized.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  uint32_t bpos = aes->bpos;
  uint32_t ilen = inlen;
  uint32_t olen = ilen - (ilen % 16);
  uint32_t ipos = 0;
  uint32_t opos = 0;

  aes->bpos = (aes->bpos + ilen) % 16;

  if (bpos > 0) {
    uint32_t want = 16 - bpos;

    if (want > ilen)
      want = ilen;

    memcpy(aes->block + bpos, in + ipos, want);

    bpos += want;
    ilen -= want;
    ipos += want;

    if (bpos < 16) {
      info.GetReturnValue().Set(
        Nan::CopyBuffer((char *)NULL, 0).ToLocalChecked());
      return;
    }

    olen += 16;
  }

  uint8_t *out = (uint8_t *)malloc(olen);

  if (out == NULL)
    return Nan::ThrowError("Could not allocate ciphertext.");

  if (ipos)
    AES_ENCRYPT(aes->block, 0, out, opos);

  while (ilen >= 16) {
    AES_ENCRYPT(in, ipos, out, opos);
    opos += 16;
    ipos += 16;
    ilen -= 16;
  }

  if (ilen > 0)
    memcpy(aes->block + 0, in + ipos, ilen);

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)&out[0], olen).ToLocalChecked());
}

NAN_METHOD(AESCipher::Final) {
  AESCipher *aes = ObjectWrap::Unwrap<AESCipher>(info.Holder());

  if (aes->bpos & FINALIZED)
    return Nan::ThrowError("Context is already finalized.");

  uint32_t left = 16 - aes->bpos;

  memset(aes->block + aes->bpos, left, left);

  AES_ENCRYPT(aes->block, 0, aes->block, 0);

  memset(&aes->key, 0, sizeof(AES_KEY));
  memset(aes->prev, 0, 16);
  aes->bpos = FINALIZED;

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&aes->block[0], 16).ToLocalChecked());

  memset(aes->block, 0, 16);
}

NAN_INLINE static bool IsNull(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;
  return obj->IsNull() || obj->IsUndefined();
}

static Nan::Persistent<v8::FunctionTemplate> aesd_constructor;

#define AES_DECRYPT(in, ipos, out, opos) do { \
  if (aes->chain) { \
    AES_decrypt(in + ipos, out + opos, &aes->key); \
    XOR(out + opos, out + opos, aes->prev); \
    memcpy(aes->prev, in + ipos, 16); \
  } else { \
    AES_decrypt(in + ipos, out + opos, &aes->key); \
  } \
} while (0)

AESDecipher::AESDecipher() {
  bits = 256;
  chain = false;
  memset(&key, 0, sizeof(AES_KEY));
  memset(&prev, 0, 16 * sizeof(uint8_t));
  memset(&block, 0, 16 * sizeof(uint8_t));
  bpos = 0;
}

AESDecipher::~AESDecipher() {}

void
AESDecipher::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(AESDecipher::New);

  aesd_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("AESDecipher").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", AESDecipher::Init);
  Nan::SetPrototypeMethod(tpl, "update", AESDecipher::Update);
  Nan::SetPrototypeMethod(tpl, "final", AESDecipher::Final);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(aesd_constructor);

  target->Set(Nan::New("AESDecipher").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(AESDecipher::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create AESDecipher instance.");

  AESDecipher *aes = new AESDecipher();

  uint32_t bits = 256;
  bool chain = false;

  if (info.Length() > 0 && !IsNull(info[0])) {
    if (!info[0]->IsNumber())
      return Nan::ThrowTypeError("First argument must be a number.");

    bits = info[0]->Uint32Value();

    if (bits != 128 && bits != 192 && bits != 256)
      return Nan::ThrowTypeError("First argument must be a number.");
  }

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("First argument must be a number.");

    chain = info[1]->BooleanValue();
  }

  aes->bits = bits;
  aes->chain = chain;

  aes->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(AESDecipher::Init) {
  AESDecipher *aes = ObjectWrap::Unwrap<AESDecipher>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("AESDecipher.init() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *key = (uint8_t *)node::Buffer::Data(buf);
  size_t keylen = node::Buffer::Length(buf);

  if (keylen != 32)
    return Nan::ThrowError("Invalid key size.");

  if (info.Length() > 1 && !IsNull(info[1])) {
    v8::Local<v8::Object> buf = info[1].As<v8::Object>();

    if (!node::Buffer::HasInstance(buf))
      return Nan::ThrowTypeError("Second argument must be a buffer.");

    uint8_t *iv = (uint8_t *)node::Buffer::Data(buf);
    size_t ivlen = node::Buffer::Length(buf);

    if (ivlen != 16)
      return Nan::ThrowError("Invalid IV size.");

    memcpy(aes->prev, iv, 16);
  } else {
    if (aes->chain)
      return Nan::ThrowTypeError("Second argument must be a buffer.");
  }

  AES_set_decrypt_key(key, aes->bits, &aes->key);
  aes->bpos = 0;

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(AESDecipher::Update) {
  AESDecipher *aes = ObjectWrap::Unwrap<AESDecipher>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("AESDecipher.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (aes->bpos & FINALIZED)
    return Nan::ThrowError("Context is already finalized.");

  const uint8_t *in = (uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  uint32_t bpos = aes->bpos;
  uint32_t ilen = inlen;
  uint32_t olen = ilen - (ilen % 16);
  uint32_t ipos = 0;
  uint32_t opos = 0;

  aes->bpos = (aes->bpos + ilen) % 16;

  if (bpos > 0) {
    uint32_t want = 16 - bpos;

    if (want > ilen)
      want = ilen;

    memcpy(aes->block + bpos, in + ipos, want);

    bpos += want;
    ilen -= want;
    ipos += want;

    if (bpos < 16) {
      info.GetReturnValue().Set(
        Nan::CopyBuffer((char *)NULL, 0).ToLocalChecked());
      return;
    }

    olen += 16;
  }

  uint8_t *out = (uint8_t *)malloc(olen);

  if (out == NULL)
    return Nan::ThrowError("Could not allocate ciphertext.");

  if (ipos)
    AES_DECRYPT(aes->block, 0, out, opos);

  while (ilen >= 16) {
    AES_DECRYPT(in, ipos, out, opos);
    opos += 16;
    ipos += 16;
    ilen -= 16;
  }

  if (ilen > 0)
    memcpy(aes->block + 0, in + ipos, ilen);

  memcpy(aes->last, out + olen - 16, 16);

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)&out[0], olen - 16).ToLocalChecked());
}

NAN_METHOD(AESDecipher::Final) {
  AESDecipher *aes = ObjectWrap::Unwrap<AESDecipher>(info.Holder());

  if (aes->bpos & FINALIZED)
    return Nan::ThrowError("Context is already finalized.");

  memset(aes->block, 0, 16);
  memset(aes->prev, 0, 16);
  memset(&aes->key, 0, sizeof(AES_KEY));
  aes->bpos = FINALIZED;

  uint8_t *blk = aes->last;

  if (aes->bpos != 0)
    return Nan::ThrowError("Bad decrypt (trailing bytes).");

  uint8_t start = 0;
  uint8_t end = 16;
  uint8_t left = blk[end - 1];

  if (left == 0 || left > 16)
    return Nan::ThrowError("Bad decrypt (padding).");

  for (uint8_t i = 0; i < left; i++) {
    end -= 1;
    if (blk[end] !== left)
      return Nan::ThrowError("Bad decrypt (padding).");
  }

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&blk[0], end).ToLocalChecked());

  memset(blk, 0, 16);
}
