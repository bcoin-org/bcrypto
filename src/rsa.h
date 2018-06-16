#ifndef _BCRYPTO_RSA_HH
#define _BCRYPTO_RSA_HH
#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10
class BRSA : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BRSA();
  ~BRSA();

private:
  static NAN_METHOD(PrivateKeyGenerate);
  static NAN_METHOD(PrivateKeyGenerateAsync);
  static NAN_METHOD(Sign);
  static NAN_METHOD(PrivateKeyVerify);
  static NAN_METHOD(Verify);
  static NAN_METHOD(PublicKeyVerify);
};
#endif

#endif
