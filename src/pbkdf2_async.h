#ifndef _BCRYPTO_PBKDF2_ASYNC_H
#define _BCRYPTO_PBKDF2_ASYNC_H

#include <node.h>
#include <nan.h>
#include "openssl/evp.h"

class PBKDF2Worker : public Nan::AsyncWorker {
public:
  PBKDF2Worker (
    v8::Local<v8::Object> &dataHandle,
    v8::Local<v8::Object> &saltHandle,
    const EVP_MD* md,
    const uint8_t *data,
    uint32_t datalen,
    const uint8_t *salt,
    uint32_t saltlen,
    uint32_t iter,
    uint32_t keylen,
    Nan::Callback *callback
  );

  virtual ~PBKDF2Worker ();
  virtual void Execute ();
  void HandleOKCallback();

private:
  const EVP_MD* md;
  const uint8_t *data;
  uint32_t datalen;
  const uint8_t *salt;
  uint32_t saltlen;
  uint32_t iter;
  uint8_t *key;
  uint32_t keylen;
};

#endif
