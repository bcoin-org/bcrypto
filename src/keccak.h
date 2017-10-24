#ifndef _BCRYPTO_KECCAK_H
#define _BCRYPTO_KECCAK_H
#include <node.h>
#include <nan.h>
#include "sha3/sha3.h"

class Keccak : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  Keccak();
  ~Keccak();

  keccak_ctx ctx;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
  static NAN_METHOD(Digest);
  static NAN_METHOD(Root);
};
#endif
