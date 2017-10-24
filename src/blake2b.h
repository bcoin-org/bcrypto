#ifndef _BCRYPTO_BLAKE2B_H
#define _BCRYPTO_BLAKE2B_H
#include <node.h>
#include <nan.h>
#include "blake2b/blake2b.h"

class Blake2b : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  Blake2b();
  ~Blake2b();

  blake2b_ctx ctx;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
  static NAN_METHOD(Digest);
  static NAN_METHOD(Root);
  static NAN_METHOD(Mac);
};
#endif
