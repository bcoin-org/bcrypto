#ifndef _BCRYPTO_ED25519_HH
#define _BCRYPTO_ED25519_HH

#include <node.h>
#include <nan.h>

class BED25519 : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BED25519();
  ~BED25519();

private:
  static NAN_METHOD(PublicKeyCreate);
  static NAN_METHOD(PublicKeyVerify);
  static NAN_METHOD(Sign);
  static NAN_METHOD(Verify);
};

#endif
