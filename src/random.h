#ifndef _BCRYPTO_RANDOM_HH
#define _BCRYPTO_RANDOM_HH
#include <node.h>
#include <nan.h>

class BRandom {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
#ifndef BCRYPTO_WITH_OPENSSL
  static NAN_METHOD(Seed);
  static NAN_METHOD(Calls);
#endif
  static NAN_METHOD(RandomBytes);
  static NAN_METHOD(RandomFill);
  static NAN_METHOD(RandomInt);
  static NAN_METHOD(RandomRange);
};

#endif
