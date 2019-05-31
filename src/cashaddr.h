#ifndef _BCRYPTO_CASHADDR_HH
#define _BCRYPTO_CASHADDR_HH
#include <node.h>
#include <nan.h>

class BCashAddr {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(Encode);
  static NAN_METHOD(Decode);
  static NAN_METHOD(Test);
};

#endif
