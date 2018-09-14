#ifndef _BCRYPTO_PBKDF2_HH
#define _BCRYPTO_PBKDF2_HH
#include <node.h>
#include <nan.h>

class BPBKDF2 : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BPBKDF2();
  ~BPBKDF2();

private:
  static NAN_METHOD(Derive);
  static NAN_METHOD(DeriveAsync);
};

#endif
