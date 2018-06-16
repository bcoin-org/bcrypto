#ifndef _BCRYPTO_ECDSA_HH
#define _BCRYPTO_ECDSA_HH

#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10
class BECDSA : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BECDSA();
  ~BECDSA();

private:
  static NAN_METHOD(PrivateKeyGenerate);
  static NAN_METHOD(PublicKeyCreate);
  static NAN_METHOD(PublicKeyConvert);
  static NAN_METHOD(Sign);
  static NAN_METHOD(PrivateKeyVerify);
  static NAN_METHOD(Verify);
  static NAN_METHOD(PublicKeyVerify);
  static NAN_METHOD(ECDH);
  static NAN_METHOD(PrivateKeyTweakAdd);
  static NAN_METHOD(PublicKeyTweakAdd);
};
#endif

#endif
