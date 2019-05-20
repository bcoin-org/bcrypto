#ifndef _BCRYPTO_MD4_HH
#define _BCRYPTO_MD4_HH
#include <node.h>
#include <nan.h>
#include "nettle/md4.h"

class BMD4 : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BMD4();
  ~BMD4();

  struct md4_ctx ctx;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
  static NAN_METHOD(Digest);
  static NAN_METHOD(Root);
  static NAN_METHOD(Multi);
};
#endif
