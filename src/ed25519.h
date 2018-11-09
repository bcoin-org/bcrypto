#ifndef _BCRYPTO_ED25519_HH
#define _BCRYPTO_ED25519_HH

#include <node.h>
#include <nan.h>

class BED25519 {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(PrivateKeyConvert);
  static NAN_METHOD(PrivateKeyTweakAdd);
  static NAN_METHOD(PublicKeyCreate);
  static NAN_METHOD(PublicKeyConvert);
  static NAN_METHOD(PublicKeyDeconvert);
  static NAN_METHOD(PublicKeyVerify);
  static NAN_METHOD(PublicKeyTweakAdd);
  static NAN_METHOD(Sign);
  static NAN_METHOD(SignTweak);
  static NAN_METHOD(Verify);
  static NAN_METHOD(Derive);
  static NAN_METHOD(Exchange);
};

#endif
