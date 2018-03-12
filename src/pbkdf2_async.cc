#include "pbkdf2_async.h"

PBKDF2Worker::PBKDF2Worker (
  v8::Local<v8::Object> &dataHandle,
  v8::Local<v8::Object> &saltHandle,
  const EVP_MD *md,
  const uint8_t *data,
  uint32_t datalen,
  const uint8_t *salt,
  uint32_t saltlen,
  uint32_t iter,
  uint32_t keylen,
  Nan::Callback *callback
) : Nan::AsyncWorker(callback)
  , md(md)
  , data(data)
  , datalen(datalen)
  , salt(salt)
  , saltlen(saltlen)
  , iter(iter)
  , key(NULL)
  , keylen(keylen)
{
  Nan::HandleScope scope;
  SaveToPersistent("data", dataHandle);
  SaveToPersistent("salt", saltHandle);
}

PBKDF2Worker::~PBKDF2Worker() {}

void
PBKDF2Worker::Execute() {
  key = (uint8_t *)malloc(keylen);

  if (key == NULL) {
    SetErrorMessage("PBKDF2 failed.");
    return;
  }

  uint32_t ret = PKCS5_PBKDF2_HMAC(
    (const char *)data, datalen, salt,
    saltlen, iter, md, keylen, key);

  if (ret <= 0) {
    free(key);
    key = NULL;
    SetErrorMessage("PBKDF2 failed.");
  }
}

void
PBKDF2Worker::HandleOKCallback() {
  Nan::HandleScope scope;

  v8::Local<v8::Value> keyBuffer =
    Nan::NewBuffer((char *)key, keylen).ToLocalChecked();

  v8::Local<v8::Value> argv[] = { Nan::Null(), keyBuffer };

  callback->Call(2, argv, async_resource);
}
