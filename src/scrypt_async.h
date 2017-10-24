#ifndef _BCRYPTO_SCRYPT_ASYNC_H
#define _BCRYPTO_SCRYPT_ASYNC_H

#include <node.h>
#include <nan.h>

class ScryptWorker : public Nan::AsyncWorker {
public:
  ScryptWorker (
    v8::Local<v8::Object> &passHandle,
    v8::Local<v8::Object> &saltHandle,
    const uint8_t *pass,
    const uint32_t passlen,
    const uint8_t *salt,
    size_t saltlen,
    uint64_t N,
    uint64_t r,
    uint64_t p,
    size_t keylen,
    Nan::Callback *callback
  );

  virtual ~ScryptWorker ();
  virtual void Execute ();
  void HandleOKCallback();

private:
  const uint8_t *pass;
  const uint32_t passlen;
  const uint8_t *salt;
  size_t saltlen;
  uint64_t N;
  uint64_t r;
  uint64_t p;
  uint8_t *key;
  size_t keylen;
};

#endif
