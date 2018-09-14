#ifndef _BCRYPTO_RANDOM_HH
#define _BCRYPTO_RANDOM_HH
#include <node.h>
#include <nan.h>

class BRandom : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BRandom();
  ~BRandom();

private:
  static NAN_METHOD(RandomFill);
};

#endif
